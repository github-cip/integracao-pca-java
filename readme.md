# Exemplos de integração com PCA - Java

O objetivo desse repositório é ilustrar com exemplos práticos como integrar com o sistema PCA.

## Canais

### Integração - api rest

Possui exemplos de integração por API REST utilizando bibliotecas.

### Integração - arquivos

Possui exemplos de integração por arquivos.

# Requisitos

* Java 11
* Maven

## Geração de certificados tipo servidor ICP-Brasil

O exemplo abaixo é útil para geração de certificados a serem utilizados em tempo de desenvolvimento e testes:

_Gera o certificado e sua chave privada:_

```
openssl req -days 3650 \
	-keyout 87654321_priv_encrypted.pem \
	-newkey rsa:2048 \
	-out 87654321.cer \
	-passout pass:pass123 \
	-set_serial 0x`(openssl rand -hex 16)` \
	-subj "/C=BR/O=ICP-Brasil/OU=RRC T001/OU=87654321/CN=participante87654321.com.br" \
	-x509
```

_Descriptografa a chave privada gerada do comando anterior:_

```
openssl pkcs8 -in ./87654321_priv_encrypted.pem \
	-nocrypt \
	-out ./87654321_priv_decrypted.pem \
	-passin pass:pass123 \
	-topk8
```

Para todos os detalhes a respeito da especificação dos certificados consulte o manual de integração e segurança.