## mcspy

mcspy is a small tool that spies on memcached traffic passing through a node and reports simple statistics about what it observes. It can be run on a machine running either a memcache client or server and will report on any number of clients/servers observed via packet capture.

Because this is best-effort based on packet capture and doesn't re-assemble streams between packets, it is not guaranteed to have 100% accuracy, but provides a good overview of what is in transit at any given time.

### Installation

```
go get github.com/theojulienne/mcspy
```

### Usage

To run a basic capture for 60 seconds and output Markdown-formatted statistics:
```
mcspy -t 60
```

If you have keys that have high cardinality due to having user IDs or similar, you can create a glob file to match key patterns instead. A glob file can be formatted like the following:
```
v1:user:*
v1:repo:*:blob:*
```

When provided, any key matching a glob will be replaced in statistics/counting by the glob pattern, which is often more useful:
```
mcspy -t 60 -g globs-in-production.txt
```

Other options are available, but most are safe to leave at default values:
```
Usage of ./mcspy:
  -f string
    	BPF filter for pcap (default "tcp and port 11211")
  -g string
    	Pattern file containing one glob per line to transform/generalise keys
  -i string
    	Interface to get packets from (default "eth0")
  -p int
    	Memcache server port (default 11211)
  -s int
    	SnapLen for pcap packet capture (default 1600)
  -t int
    	Number of seconds to capture, or 0 to capture forever
```
