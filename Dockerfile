FROM node:26-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
# Only what runs. Keys arrive as runtime secrets, never in the image.
COPY seller.mjs seller-lib.mjs og.png ./
ENV NODE_ENV=production SELLER_PORT=8080
EXPOSE 8080
CMD ["node", "seller.mjs"]
