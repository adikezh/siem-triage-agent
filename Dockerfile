FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /triage .
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /triage /triage
ENTRYPOINT ["/triage"]
CMD ["serve"]
