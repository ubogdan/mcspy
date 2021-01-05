all:
	docker build -t mcspy-build .
	docker run --rm --entrypoint /bin/sh mcspy-build -c "cat /apps/mcspy/mcspy" > mcspy.linux
