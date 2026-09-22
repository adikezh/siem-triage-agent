FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /triage .
RUN mkdir -p /app/data && chown 65532:65532 /app/data
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /triage /triage
COPY --from=build --chown=nonroot:nonroot /app/data /app/data
COPY --from=build /src/testdata /app/testdata
ENTRYPOINT ["/triage"]
CMD ["serve"]
