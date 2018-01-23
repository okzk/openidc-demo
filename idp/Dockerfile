FROM golang

RUN go get github.com/go-chi/chi github.com/patrickmn/go-cache github.com/google/uuid github.com/dgrijalva/jwt-go
COPY main.go /go/src/github.com/okzk/openidc-demo/idp/
RUN go get github.com/okzk/openidc-demo/idp

ENV FQDN=localhost

CMD ["/go/bin/idp"]
