FROM swift:5.8-jammy as builder
ADD . /src
WORKDIR /src
RUN swift build -c release -Xswiftc -sanitize=fuzzer,address

FROM swift:5.8-jammy-slim
COPY --from=builder /PhoneNumberKit/.build/release/ /release
ENTRYPOINT ["/release/PhoneNumberKitFuzzer"]