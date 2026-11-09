FROM scratch
COPY dnsmock /dnsmock
ENTRYPOINT ["/dnsmock"]
