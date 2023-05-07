FROM swift:5.8-jammy as builder
ADD . /src
WORKDIR /src
RUN swift build -c release

FROM swift:5.8-jammy-slim
COPY --from=builder /src/.build/release/ /release
ENTRYPOINT ["/release/PhoneNumberKitFuzzer"]