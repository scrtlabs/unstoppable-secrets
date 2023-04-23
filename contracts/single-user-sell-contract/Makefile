.PHONY: build run-localsecret _test kill-localsecret 

build:
	RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown
	cp -f ../../target/wasm32-unknown-unknown/release/unstoppable_secrets_single_user.wasm contract.wasm

run-localsecret:
	sudo docker run -it --rm -p 1317:1316 --name localsecret ghcr.io/scrtlabs/localsecret:v1.8.0

kill-localsecret:
	sudo docker rm -f localsecret

_test:
	cd tests
	yarn test

test: build run-localsecret _test kill-localsecret 

find-floating-points: build
	wasm2wat contract.wasm | grep -c -P 'f(64|32)'
