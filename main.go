package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/olekukonko/tablewriter"
	"github.com/ryanuber/go-glob"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var captureTime = flag.Int("t", 0, "Number of seconds to capture, or 0 to capture forever")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var memcachePort = flag.Int("p", 11211, "Memcache server port")
var filter = flag.String("f", "tcp and port 11211", "BPF filter for pcap")
var patternGlobs = flag.String("g", "", "Pattern file containing one glob per line to transform/generalise keys")

type Party struct {
	address gopacket.Endpoint
	port    uint16
}

func (p *Party) String() string {
	return fmt.Sprintf("%v:%v", p.address, p.port)
}

type Endpoints struct {
	src, dst         gopacket.Endpoint
	srcPort, dstPort uint16
}

func (e *Endpoints) Client() Party {
	return Party{address: e.src, port: e.srcPort}
}

func (e *Endpoints) Server() Party {
	return Party{address: e.dst, port: e.dstPort}
}

func (e *Endpoints) String() string {
	return fmt.Sprintf("%v:%v <-> %v:%v", e.src, e.srcPort, e.dst, e.dstPort)
}

type MemcacheMessage struct {
	endpoints     Endpoints
	clientRequest bool

	command string
	keys    map[string]bool
}

type SimpleKeyCounter struct {
	counts map[string]int
}

func NewSimpleKeyCounter() *SimpleKeyCounter {
	return &SimpleKeyCounter{
		counts: map[string]int{},
	}
}

func (c *SimpleKeyCounter) Inc(key string) {
	if curr, ok := c.counts[key]; ok {
		c.counts[key] = curr + 1
	} else {
		c.counts[key] = 1
	}
}

func (c *SimpleKeyCounter) PrintTable(out *os.File) {
	for k, v := range c.counts {
		fmt.Fprintf(out, "| %s | %d |\n", k, v)
	}
}

type MemcacheSnooper struct {
	inProgress map[Endpoints]MemcacheMessage

	seenMessagesByConnection *SimpleKeyCounter
	seenMessagesByClient     *SimpleKeyCounter
	seenMessagesByServer     *SimpleKeyCounter
	seenMessagesByCommand    *SimpleKeyCounter

	getsByKey *SimpleKeyCounter
	hitsByKey *SimpleKeyCounter
	missByKey *SimpleKeyCounter

	keyPatternGlobs []string
}

func (m *MemcacheMessage) ParsePayload(payload string) error {
	reader := bufio.NewReader(strings.NewReader(payload))
	for {
		s, err := reader.ReadString(' ')
		if err != nil && err != io.EOF {
			return err
		}

		cmd := strings.ToUpper(strings.TrimSpace(s))
		if cmd == "END" {
			// if we have no results, we are a VALUE result with no results for simplicity
			if m.command == "" {
				m.command = "VALUE"
			}
			return nil // this ends a get/multi get
		}
		if cmd != "GET" && cmd != "SET" && cmd != "VALUE" {
			return errors.New("Unknown message") // we don't understand this one
		}

		if err == io.EOF {
			break
		}

		m.command = cmd

		if cmd == "GET" {
			// rest of line is keys
			keys, err := reader.ReadString('\n')
			if err != nil && err != io.EOF { // allow EOF for single-value GETs
				return err
			}

			for _, key := range strings.Split(strings.TrimSpace(keys), " ") {
				m.keys[strings.TrimSpace(key)] = true
			}
		} else {
			// single key
			key, err := reader.ReadString(' ')
			if err != nil && err != io.EOF { // allow EOF for single-value GETs
				return err
			}

			m.keys[strings.TrimSpace(key)] = true
		}

		if cmd != "VALUE" {
			break // VALUE is the only type we continue to parse past 1 command per packet
		}

		// flags
		_, err = reader.ReadString(' ')
		if err != nil {
			return err
		}

		// size
		commandFromBytes, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		// now read the bytes themselves
		byteSizeStr := strings.Split(commandFromBytes, " ")[0]
		byteSize, err := strconv.Atoi(strings.TrimSpace(byteSizeStr))
		if err != nil {
			return err
		}
		reader.Discard(byteSize)

		// and the newline characters after that
		_, err = reader.ReadString('\n')
		if err != nil {
			return err
		}

		// then the next VALUE or END continues...
	}

	if m.command == "" {
		return errors.New("Did not parse a command")
	}

	return nil
}

func (m *MemcacheMessage) String() string {
	return fmt.Sprintf("MemcacheMessage<cmd:%v keys:%v nodes:%v>", m.command, m.keys, m.endpoints.String())
}

func (s *MemcacheSnooper) handlePacket(packet gopacket.Packet) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	netFlow := netLayer.NetworkFlow()
	src, dst := netFlow.Endpoints()

	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	tcp, _ := transportLayer.(*layers.TCP)

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return
	}

	msg := MemcacheMessage{}
	msg.keys = map[string]bool{}

	if tcp.DstPort == layers.TCPPort(*memcachePort) {
		msg.endpoints.src = src
		msg.endpoints.dst = dst
		msg.endpoints.srcPort = uint16(tcp.SrcPort)
		msg.endpoints.dstPort = uint16(tcp.DstPort)
		msg.clientRequest = true
	} else {
		msg.endpoints.src = dst
		msg.endpoints.dst = src
		msg.endpoints.srcPort = uint16(tcp.DstPort)
		msg.endpoints.dstPort = uint16(tcp.SrcPort)
		msg.clientRequest = false
	}

	payload := string(applicationLayer.Payload())
	if err := msg.ParsePayload(payload); err != nil {
		// fmt.Println(err)
		return
	}

	if msg.clientRequest {
		s.inProgress[msg.endpoints] = msg
		s.handleRequest(msg)
	} else if last, ok := s.inProgress[msg.endpoints]; ok {
		s.handleResponse(last, msg)
	}
}

func (s *MemcacheSnooper) handleRequest(req MemcacheMessage) {
	s.seenMessagesByCommand.Inc(req.command)

	if req.command == "GET" {
		// we can ignore GETs, because we'll handle them on response
		return
	}

	connection := req.endpoints
	client := req.endpoints.Client()
	server := req.endpoints.Server()

	s.seenMessagesByConnection.Inc(connection.String())
	s.seenMessagesByClient.Inc(client.String())
	s.seenMessagesByServer.Inc(server.String())
}

func (s *MemcacheSnooper) handleResponse(req MemcacheMessage, resp MemcacheMessage) {
	if resp.command != "VALUE" {
		// nothing else should have a response that we handle
		return
	}

	for key := range req.keys {
		keyPattern := s.keyToPattern(key)
		s.getsByKey.Inc(keyPattern)

		if _, ok := resp.keys[key]; ok {
			s.hitsByKey.Inc(keyPattern)
		} else {
			s.missByKey.Inc(keyPattern)
		}
	}
}

func (s *MemcacheSnooper) keyToPattern(key string) string {
	for _, pattern := range s.keyPatternGlobs {
		if glob.Glob(pattern, key) {
			return pattern
		}
	}
	return key
}

func (s *MemcacheSnooper) listen() {
	if handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(*filter); err != nil {
		panic(err)
	} else {
		var timer *time.Timer
		var timerChan <-chan time.Time

		if *captureTime > 0 {
			timer = time.NewTimer(time.Duration(*captureTime) * time.Second)
			defer timer.Stop()
			timerChan = timer.C
			fmt.Printf("Listening for %d seconds...\n", *captureTime)
		} else {
			timerChan = make(<-chan time.Time)
			fmt.Printf("Listening...\n")
		}

		sigChan := make(chan os.Signal)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case packet := <-packetSource.Packets():
				s.handlePacket(packet)
			case <-timerChan:
				return
			case <-sigChan:
				return
			}
		}
	}
}

func markdownTableWriter(out *os.File) *tablewriter.Table {
	table := tablewriter.NewWriter(out)
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	return table
}

func (s *MemcacheSnooper) report() {
	out := os.Stdout

	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "Connections: %d\n", len(s.inProgress))

	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "## Commands by connection\n")
	s.seenMessagesByConnection.PrintTable(out)

	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "## Commands by client\n")
	s.seenMessagesByClient.PrintTable(out)

	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "## Commands by server\n")
	s.seenMessagesByServer.PrintTable(out)

	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "## Command counts\n")
	s.seenMessagesByCommand.PrintTable(out)

	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "## Keyspace\n")
	table := markdownTableWriter(os.Stdout)
	table.SetHeader([]string{"Key Pattern", "Gets", "Hits", "Misses", "Hit %"})
	rows := [][]string{}
	for key, getCount := range s.getsByKey.counts {
		hitCount := s.hitsByKey.counts[key]
		missCount := s.missByKey.counts[key]
		rows = append(rows, []string{
			"`" + key + "`",
			strconv.Itoa(getCount),
			strconv.Itoa(hitCount),
			strconv.Itoa(missCount),
			strconv.Itoa((100*hitCount)/getCount) + "%",
		})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		numA, _ := strconv.Atoi(rows[i][3])
		numB, _ := strconv.Atoi(rows[j][3])
		return numA > numB
	})

	table.AppendBulk(rows)
	table.Render()
}

func loadGlobs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return []string{}, err
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var globs []string

	for scanner.Scan() {
		globs = append(globs, scanner.Text())
	}

	return globs, nil
}

func main() {
	flag.Parse()

	var globs []string
	var err error

	if *patternGlobs != "" {
		globs, err = loadGlobs(*patternGlobs)
		if err != nil {
			log.Fatalf("Failed to read glob file: %v", err)
		}
	}

	snooper := MemcacheSnooper{
		inProgress:               map[Endpoints]MemcacheMessage{},
		seenMessagesByConnection: NewSimpleKeyCounter(),
		seenMessagesByClient:     NewSimpleKeyCounter(),
		seenMessagesByServer:     NewSimpleKeyCounter(),
		seenMessagesByCommand:    NewSimpleKeyCounter(),

		getsByKey: NewSimpleKeyCounter(),
		hitsByKey: NewSimpleKeyCounter(),
		missByKey: NewSimpleKeyCounter(),

		keyPatternGlobs: globs,
	}

	snooper.listen()
	snooper.report()
}
