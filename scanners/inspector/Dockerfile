FROM node:22-slim
WORKDIR /app

RUN npx @modelcontextprotocol/inspector@latest --help || true

EXPOSE 6274

# Inspector is launched on-demand; default entrypoint is the inspector
ENTRYPOINT ["npx", "@modelcontextprotocol/inspector"]
