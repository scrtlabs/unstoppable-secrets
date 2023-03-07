all:
	$(MAKE) -C .. build

run-localsecret:
	docker run -it --rm -p 1317:1316 --name localsecret ghcr.io/scrtlabs/localsecret:v1.8.0

kill-localsecret:
	docker rm -f localsecret