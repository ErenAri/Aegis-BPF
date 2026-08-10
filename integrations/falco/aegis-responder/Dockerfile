# aegis-responder — static, distroless, stdlib-only.
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /aegis-responder .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /aegis-responder /aegis-responder
EXPOSE 8080
ENTRYPOINT ["/aegis-responder"]
