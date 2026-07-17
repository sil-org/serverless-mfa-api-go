FROM golang:1.26

RUN adduser user

WORKDIR /src

RUN curl -sSfL --proto "=https" https://raw.githubusercontent.com/cosmtrek/air/master/install.sh | \
  sh -s -- -b /usr/local/bin && \
  git config --global --add safe.directory /src

COPY ./ .
RUN for i in 1 2 3; do \
    go mod download && break; \
    if [ "$i" -eq 3 ]; then exit 1; fi; \
    sleep 5; \
  done && \
  git config --global --add safe.directory /src

EXPOSE 8080

CMD ["air"]
