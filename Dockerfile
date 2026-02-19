FROM golang:1.25

RUN adduser user

WORKDIR /src

RUN curl -sSfL --proto "=https" https://raw.githubusercontent.com/cosmtrek/air/master/install.sh | \
  sh -s -- -b /usr/local/bin && \
  git config --global --add safe.directory /src

COPY ./ .
RUN go get ./... && \
  git config --global --add safe.directory /src

EXPOSE 8080

CMD ["air"]
