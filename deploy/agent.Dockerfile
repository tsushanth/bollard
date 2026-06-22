# A stand-in "agent": a real MCP client (Python stdlib only). In production this
# is your agent runtime; here it exists to drive the MCP server and attempt
# egress from inside the cage.
FROM alpine:3.20
RUN apk add --no-cache python3
CMD ["sleep", "infinity"]
