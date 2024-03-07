TARGET = bin/sg2csv

.PHONY: all cleanup
all: $(TARGET)

$(TARGET): main.go
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-w -s -extldflags="-static"' -o $@ $<



cleanup:
	@rm -f $(TARGET)
