FROM golang:buster

WORKDIR /go/src/app
COPY go.mod go.sum ./
RUN go mod download -x
RUN apt-get update
COPY scripts/ ./scripts/
RUN ./scripts/install_linux_deps.sh

COPY COPYING ./
COPY Makefile ./
COPY crypto/ ./crypto/

RUN make crypto/libs/$(./scripts/ostype.sh)/$(./scripts/archtype.sh)/lib/libsodium.a

COPY installer/ ./installer/
COPY cmd/ ./cmd/

RUN make node_exporter

COPY . .

RUN make

RUN go get golang.org/x/perf/cmd/benchstat

RUN cd crypto; go test -v

CMD ['/go/src/app/run-purego-benchmarks.sh']
