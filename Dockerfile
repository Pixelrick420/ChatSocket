FROM gcc:latest

WORKDIR /app

RUN apt-get update && apt-get install -y libssl-dev

COPY . .

RUN chmod +x Server/run.sh

EXPOSE 2077

CMD ["./Server/run.sh"]
