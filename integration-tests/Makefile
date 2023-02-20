all:
	$(MAKE) -C .. build

run-localsecret:
	docker run -it --rm -p 1317:1317 --name localsecret ghcr.io/scrtlabs/localsecret:v1.6.1

kill-localsecret:
	docker rm -f localsecret