FROM node:22-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
COPY package.json .
RUN npm install
COPY tsconfig.json .
COPY src/ ./src/
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
