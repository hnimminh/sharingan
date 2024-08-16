<p align="center">
  <img width="256" src="https://github.com/user-attachments/assets/8197fcd7-d608-4e32-a705-abf1a7a44a42">  
</p>

<p align="center">
  <a href="LICENSE.md" target="_blank">
    <img src="https://badgen.net/badge/license/MIT/blue" alt="">
  </a>
</p>

<p align="center">
  <br>
  <strong>Sharingan</strong>
  <br>
  <code>-- work in progress --</code>
  <br><br>
</p>


## Build

```
# prerequisite: libpcap-dev
env GOOS=linux GOARCH=amd64 go build -o sharingan cmd/sharingan/main.go
```

## Dev Environment
`docker-compose --file docker-compose.dev.yml up --build`

### Get start
`sharingan -d -i any -appfiter esl`


