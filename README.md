# Envio de pacotes Ethernet Raw e Repetidor Wi-Fi via LoRa ESP32
Trabalho para a disciplina de Tecnologia e Comunicação de Dados - DC UFSCar - 2018
Alunos:
- Caio Augusto Silva - 628280
- Luis Felipe Tomazini - 595098

O trabalho consiste de 2 partes:
- Um programa cliente e um servidor que trocam pacotes Ethernet em um formato específico usando um Ethertype definido arbitráriamente (0x1996)
- Um software para a placa ESP32, que inicializa um access point WiFi e repete os pacotes do tipo 0x1996 enviados na rede via tecnologia LoRa.
## Instruções de uso
### Parte 1: Programas de envio de pacotes Ethernet
O trabalho possui um programa cliente, que envia um pacote e aguarda uma resposta, e um programa servidor, que aguarda um pacote, exibe seu conteudo e envia um resposta de recebimento. São disponibilizadas algumas opções de codificação dos dados.
#### Compilação
Abra um terminal na pasta T1 do projeto e execute:
```
gcc cliente.c -o cliente.app -lm
gcc servidor.c -o servidor.app -lm
```

#### Utilização
```
./servidor interface myName
./cliente interface MACaddr sourceName destinationName message encoding
```
##### Encodings:
-n: NRZ
-m: Manchester
-i: NRZI
-f: 4B5B

### Parte 2: 
#### Configuração do ambiente de Desenvolvimento
Configure o ambiente de desenvolvimento para o ESP32 como descrito na documentação:
https://esp-idf.readthedocs.io/en/latest/get-started/index.html#setup-toolchain
Abra um terminal na pasta T2 do projeto.
#### Configuração de Compilação
Para configurar o nome do Access Point execute:
```
make menuconfig
```
E defina o nome na opção "WiFi Configuration".
A porta utilizada para comunicação com a placa ESP32 também pode ser definida em "Serial flasher config". Por padrão ela é definida como ``/dev/ttyUSB0``.

#### Compilação e transferência para a placa
Para rodar o projeto na placa execute:
```
make flash
```
Aguarde a compilação. Após enviado para a placa é possível conferir a saída do código executando:
```
make monitor
```


