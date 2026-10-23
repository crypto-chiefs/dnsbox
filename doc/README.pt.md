# DNSBox — DNS e HTTPS auto-hospedados para nomes de host baseados em IP

[English](../README.md) · [Implantação e redes privadas](deployment.md) · [Configuração](configuration.md) · [Notas de atualização](migration-v0.5.md)

O DNSBox combina um servidor DNS autoritativo com um proxy reverso HTTPS. Um nome de host como `192-168-1-50.home.arpa` identifica o IP de um backend. As respostas DNS apontam para **o proxy DNSBox**, que termina a conexão TLS e encaminha HTTP para esse backend. Há suporte a IPv4 com pontos ou hífens, IPv6 com hífens, atualização de conexões para WebSocket e armazenamento persistente de certificados.

Estão disponíveis dois modos TLS:

- **`acme`**: certificados para nomes de host em um domínio que você controla, usando ACME DNS-01 (Let's Encrypt por padrão). Seu DNS autoritativo precisa estar acessível publicamente.
- **`local`**: uma autoridade certificadora (CA) local e persistente para redes privadas, sem DNS público, acesso à Internet ou encaminhamento de portas. Os clientes precisam confiar na CA gerada.

Os certificados cobrem nomes de host DNS, não endereços IP isolados. Executar o software não concede controle sobre `dnsbox.io`. A disponibilidade e a configuração do serviço público `dnsbox.io` são independentes deste repositório.

## Início rápido em uma rede privada

Exemplo: máquina virtual DNSBox `192.168.1.2`, aplicação HTTP `192.168.1.50:80`, zona privada `home.arpa`.

Baixe o [arquivo da versão](https://github.com/crypto-chiefs/dnsbox/releases) correspondente, verifique-o usando `checksums.txt` e execute:

```bash
./dnsboxd \
  --domain=home.arpa --ip=192.168.1.2 --ns=ns1 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443 \
  --data-dir=/var/lib/dnsbox
```

O processo precisa de acesso de escrita ao diretório de dados e de permissão para escutar nessas portas. Configure o resolvedor da sua LAN para encaminhar **a zona `home.arpa`** para `192.168.1.2`; o DNSBox não fornece um serviço DNS recursivo de uso geral.

Na primeira solicitação de certificado, o DNSBox cria `/var/lib/dnsbox/ca/root.crt` e sua chave privada. Copie com segurança **somente `root.crt`** para os clientes e instale-o no armazenamento de autoridades certificadoras confiáveis. Para testar uma única requisição, use:

```bash
curl --cacert root.crt \
  --resolve 192-168-1-50.home.arpa:443:192.168.1.2 \
  https://192-168-1-50.home.arpa/
```

Você pode criar a CA e um certificado de servidor antes de iniciar o serviço, usando a mesma configuração com a opção adicional `--issue=192-168-1-50.home.arpa`. No modo local, esse comando grava o certificado e termina sem abrir portas de escuta. Consulte o [guia de implantação privada](deployment.md).

## Instalação

Instalador para Linux e macOS, fixado na versão publicada:

```bash
curl --fail --location \
  https://raw.githubusercontent.com/crypto-chiefs/dnsbox/v0.5.2/scripts/install.sh \
  -o install-dnsbox.sh
# Revise o script e, em seguida, execute:
bash install-dnsbox.sh \
  --domain=home.arpa --ip=192.168.1.2 \
  --tls-mode=local --allowed-cidrs=192.168.1.0/24 \
  --dns-listen=192.168.1.2:53 --https-listen=192.168.1.2:443
```

O instalador verifica a soma SHA-256 do arquivo, instala em `~/.dnsbox` e usa `~/.dnsbox/data` para dados persistentes em uma instalação nova. Ele cria um serviço systemd somente quando o systemd está em execução. Use `--no-systemd` para iniciar manualmente, inclusive no Calculate Linux/OpenRC:

```bash
~/.dnsbox/run-dnsbox
```

O arquivo gerado `~/.dnsbox/dnsbox.env` armazena a configuração e é preservado nas atualizações. Executar o instalador novamente atualiza os binários; para alterar as configurações, edite o arquivo de ambiente existente. Nem o instalador nem o desinstalador altera o resolvedor do sistema ou apaga os logs do sistema. No Windows, extraia o arquivo e execute `dnsboxd.exe` com as mesmas opções.

## Certificados públicos e NAT

Para o modo ACME, delegue um domínio ou subdomínio **que você controla** ao seu servidor DNSBox autoritativo. Forneça registros públicos de glue ou de endereço para o servidor de nomes, conforme necessário. Encaminhe **a porta 53 tanto por UDP quanto por TCP** para o DNSBox. Permita conexões HTTPS de saída para ACME.

O DNS-01 **não** precisa da porta 80 de entrada. A porta 443 só precisa estar acessível aos clientes que usam o proxy HTTPS. O backend HTTP pode permanecer privado: permita a rede dele com `--allowed-cidrs`. Uma rede completamente isolada precisa usar o modo TLS local.

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --acme-email=admin@example.com --data-dir=/var/lib/dnsbox
```

Substitua os nomes e endereços de exemplo pelos seus. `--ip` é o endereço usado pelos clientes para acessar o DNSBox, não o endereço do backend. Um proxy IPv4 retorna registros A; um proxy IPv6 retorna registros AAAA, independentemente da família IP do backend.

## Vários nós DNS e ACME

Use a mesma lista estática `--nameservers` em todos os nós. Cada rótulo deve ser exclusivo e cada endereço deve ser um IP unicast literal; os valores locais de `--ns` e `--ip` precisam corresponder a uma entrada. Todos os nós publicam o mesmo conjunto de NS, os mesmos endereços dos nós e o mesmo servidor primário no SOA. Sem essa opção, o DNSBox publica somente seu próprio servidor de nomes. Mantenha a delegação na zona superior, os registros glue e quaisquer substituições personalizadas de endereços NS consistentes entre si.

Para usar ACME com vários nós autoritativos, configure `--cluster-file` em cada nó para replicar os valores TXT temporários do DNS-01. Use a mesma zona, as mesmas regras de acesso aos backends e os mesmos registros personalizados em todos os nós. Exemplo para o primeiro nó:

```bash
./dnsboxd --domain=apps.example.com --ip=203.0.113.10 --ns=ns1 \
  --nameservers=ns1=203.0.113.10,ns2=203.0.113.11,ns3=203.0.113.12 \
  --cluster-file=/etc/dnsbox/cluster.json --data-dir=/var/lib/dnsbox
```

Arquivo `cluster.json` desse nó:

```json
{
  "listen": "0.0.0.0:8443",
  "certificate": "cluster-node.crt",
  "private_key": "cluster-node.key",
  "ca_certificate": "cluster-ca.crt",
  "peers": ["https://203.0.113.11:8443", "https://203.0.113.12:8443"]
}
```

Cada nó lista todos os outros usando uma URL HTTPS explícita com IP e porta. Restrinja o acesso à porta do cluster a esses nós. Use uma CA dedicada ao cluster e um certificado e uma chave separados para cada nó. O certificado precisa incluir o IP do nó no SAN e permitir autenticação de servidor e de cliente. Os caminhos são relativos ao arquivo JSON. Proteja os arquivos da CA e de TLS e mantenha a chave privada da CA offline. O TLS mútuo autentica os nós; somente valores TXT temporários são replicados, nunca certificados HTTPS, chaves privadas ou a CA do modo local. As variáveis de ambiente correspondentes são `DNSBOX_NAMESERVERS` e `DNSBOX_CLUSTER_FILE`.

## Registros ALIAS no ápice da zona

Para apontar o ápice da zona para um nome de hospedagem externo, adicione o seguinte ao arquivo selecionado por `--records-file`:

```text
apps.example.com ALIAS landing.example.net.
```

Configure esse provedor de hospedagem para servir seu domínio raiz e HTTPS. O DNSBox resolve o destino antes de o serviço DNS ficar pronto, atualiza-o em segundo plano e responde usando os registros A/AAAA em cache, sem resolver nomes durante o processamento das consultas. Uma falha na resolução inicial impede a inicialização; um cache com mais de uma hora resulta em SERVFAIL para consultas A/AAAA. ALIAS só é permitido no ápice, precisa apontar para um nome fora da zona e não pode coexistir ali com A, AAAA ou CNAME. NS, SOA, TXT, MX e os nomes de host do proxy baseados em IP continuam disponíveis. As listas estáticas de servidores de nomes, a replicação de TXT em cluster e ALIAS exigem v0.5.2 ou posterior.

## Segurança e compatibilidade

Por padrão, somente endereços públicos de backend são permitidos. Uma lista explícita `--allowed-cidrs` restringe o acesso às redes indicadas e permite implantações privadas. Mantenha uma implantação privada escutando nas interfaces da LAN e protegida pelo seu firewall.

A API de gerenciamento usa `127.0.0.1:8080` por padrão. Alterações de registros exigem um token Bearer configurado; um valor vazio `--api-listen=` desativa a API. Os antigos endpoints de compartilhamento de certificados sem autenticação foram removidos. Cada nó mantém seu próprio armazenamento de certificados.

Os certificados e as chaves privadas são armazenados de forma persistente no diretório de dados. Faça backup desse diretório com segurança. Os arquivos `certs/<hostname>.crt` e `.key` podem ser usados por outro serviço, como o ocserv, mas o proxy reverso HTTP do DNSBox não é um proxy OpenConnect/DTLS. Consulte as [instruções para exportar certificados](deployment.md#certificates-for-ocserv-or-another-service).

Leia as [notas de migração para a v0.5](migration-v0.5.md) antes de atualizar a partir da v0.4.

## Desenvolvimento

Use a versão de Go declarada em [go.mod](../go.mod).

```bash
go test -race ./...
go vet ./...
bash scripts/test-install.sh
go build ./cmd/dnsboxd
```

A integração contínua de publicação executa as verificações antes de publicar arquivos para Linux, macOS e Windows em amd64 e arm64. [Licença MIT](../LICENSE).