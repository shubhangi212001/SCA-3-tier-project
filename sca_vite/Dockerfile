FROM node:18-alpine

WORKDIR /sca_vite

EXPOSE 3000

COPY .*.json ./

RUN npm install

COPY . ./

CMD ["npm", "run", "dev"]
