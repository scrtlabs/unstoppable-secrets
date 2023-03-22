.PHONY: build run-localsecret _test kill-localsecret 

build:
	RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown
	cp ../../target/wasm32-unknown-unknown/release/unstoppable_secrets_paillier.wasm contract.wasm

run-localsecret:
	docker run -it --rm -p 1317:1316 --name localsecret ghcr.io/scrtlabs/localsecret:v1.8.0

kill-localsecret:
	docker rm -f localsecret

_test:
	cd tests
	yarn test

test: build run-localsecret _test kill-localsecret 
