# Relatório de Threat Intelligence – IP **216.238.109.50**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io (sem resultados).  
> **Última coleta Shodan**: 2025‑10‑17.  

---

## 1. Resumo Executivo
O endereço **216.238.109.50** pertence à nuvem da **Vultr** (ASN AS20473 – The Constant Company, LLC) e está localizado em **Osasco, São Paulo, Brasil**. O host apresenta as portas **22 (SSH), 80 (HTTP), 443 (HTTPS), 500 (UDP – IKE VPN) e 7011 (TCP – serviço não identificado)**. Os banners revelam um servidor **OpenSSH 7.6p1** e um túnel VPN IKE ativo.  
Diversos domínios de **curto tempo de vida** (ex.: `regularizandocpf.com`, `rendaverificada.com`, `centralregularizacao.com`) apontam para este IP, todos exibindo páginas em português com aparência de sites de “regularização” de CPF, renda, etc., tipicamente associadas a **phishing e fraudes financeiras**. As tags do Shodan (“cloud”, “vpn”) reforçam a natureza de hospedeiro de serviços VPN e web. Não foram encontradas vulnerabilidades CVE explícitas no relatório, porém o OpenSSH 7.6p1 possui vulnerabilidades conhecidas.

---

## 2. Análise de Comportamento
| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Tags Shodan** | `cloud`, `vpn` | Hospedado em nuvem e oferece serviço VPN – uso legítimo ou para mascaramento de atividades maliciosas. |
| **Porta 500/UDP (IKE VPN)** | Payload IKE exibido, sem criptografia | Indica um serviço de VPN ativo, possivelmente usado para **túnel de tráfego malicioso** ou para ocultar a origem de ataques. |
| **Porta 22/SSH aberta** | OpenSSH 7.6p1, banner público | Facilidade de acesso remoto; pode ser alvo de **brute‑force** ou já estar comprometido como ponto de comando e controle (C2). |
| **Portas 80/443 HTTP(S)** | Resposta 404 em 80; HTTPS ativo nos domínios investigados | Hospedagem de múltiplos sites de aparência fraudulenta (phishing/ scams). |
| **Domínios de curto prazo** | Idade entre 0‑14 dias, conteúdo de “regularização” de documentos | Estratégia típica de **phishing**: registrar rapidamente domínios, usar certificados válidos (TLS 89 dias) para ganhar confiança. |
| **Ausência de CVEs listadas** | Shodan não mostrou vulnerabilidades específicas | Não há vulnerabilidades expostas diretamente, mas o software (OpenSSH 7.6p1) tem CVEs conhecidos (ex.: CVE‑2018‑15473, CVE‑2020‑15778). |
| **Presença em feeds de ameaças** | Não fornecido, porém tags e comportamento sugerem inclusão em listas de **abuse** de nuvem. | Recomenda‑se verificação em fontes externas (AbuseIPDB, Spamhaus, etc.). |

**Conclusão comportamental:** O IP funciona como **infraestrutura de hospedagem de sites fraudulentos** e oferece serviços VPN/SSH que podem ser utilizados para **túnel e controle remoto**. Não há evidência direta de ser parte de um botnet conhecido, mas o conjunto de serviços e a natureza dos domínios apontam para uso malicioso.

---

## 3. Superfície de Ataque
### Portas abertas e serviços
| Porta | Protocolo | Serviço / Banner | Observações |
|-------|-----------|------------------|------------|
| 22    | TCP | OpenSSH 7.6p1 (banner completo) | Possível vetor de força‑bruta ou ponto de C2. |
| 80    | TCP | HTTP – responde com **404 Not Found** | Servidor web ativo; usado para redirecionamento ou teste. |
| 443   | TCP | HTTPS – TLS 1.2/1.3 (certificado válido 89 dias) | Hospeda os domínios de phishing. |
| 500   | UDP | IKE (VPN) – sem criptografia | Serviço VPN aberto, pode ser usado para encapsular tráfego malicioso. |
| 7011  | TCP | **Não descrito** (exposto) | Necessita de investigação adicional (possível serviço interno ou backdoor). |

### Vulnerabilidades (CVEs) associadas
- **OpenSSH 7.6p1** possui vulnerabilidades conhecidas, entre elas:
  - **CVE‑2018‑15473** – Enumeração de usuários via handshake SSH.
  - **CVE‑2020‑15778** – Falha de “username enumeration” e possibilidade de negação de serviço.
- **IKE/UDP 500** – Versões antigas do protocolo podem ser vulneráveis a ataques de DoS ou “Man‑in‑the‑Middle” se configuradas inadequadamente (sem criptografia, como indicado).  
> *Nota:* O Shodan não listou CVEs específicas para este host; as vulnerabilidades acima são inferidas a partir das versões dos softwares detectados.

---

## 4. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS20473** – *The Constant Company, LLC* |
| **ISP / Provedor** | *The Constant Company, LLC* (operadora de data‑center) |
| **Organização** | *Vultr Holdings, LLC* (provedor de cloud) |
| **País** | Brasil |
| **Região / Estado** | São Paulo |
| **Cidade** | Osasco |
| **Latitude / Longitude** | -23.5325, -46.7917 |
| **Hostname (RDNS)** | `216.238.109.50.vultrusercontent.com` |
| **Domínios associados** | `regularizandocpf.com`, `rendaverificada.com`, `centralregularizacao.com`, `portalregularizacao.com`, `regularizesuadivida.com`, `regularizesuarenda.com`, dentre outros. |

---

## 5. Recomendações de Investigação e Mitigação
1. **Correlacionar com feeds de ameaças** – Verificar o IP em fontes como AbuseIPDB, Spamhaus, VirusTotal, OTX, e em listas de bloqueio de provedores de e‑mail/web.
2. **Revisar logs de firewall** – Identificar tráfego de entrada nas portas 22, 500 e 7011; buscar tentativas de força‑bruta ou conexões VPN incomuns.
3. **Monitorar tentativas de login SSH** – Habilitar alertas de múltiplas falhas de autenticação e, se possível, limitar acesso a IPs confiáveis (allowlist) ou mover SSH para porta não padrão.
4. **Analisar tráfego VPN (porta 500)** – Capturar pacotes para identificar se há troca de chaves, uso de criptografia ou tráfego anômalo (ex.: tunneling de C2).
5. **Varredura de vulnerabilidades adicional** – Executar scanners (Nessus, OpenVAS, Nmap scripts) focados em OpenSSH 7.6p1 e possíveis serviços na porta 7011.
6. **Inspeção de conteúdo web** – Baixar e analisar o código-fonte das páginas hospedadas (phishing, scripts maliciosos, redirecionamentos) e registrar hashes nos repositórios de inteligência.
7. **Contatar o provedor (Vultr)** – Notificar o abuse@vultr.com com evidências (hosts, domínios phishing) para possível remoção ou suspensão da instância.
8. **Bloqueio em perímetro** – Se o IP for considerado malicioso para a sua organização, aplicar bloqueio nas camadas de perímetro (firewall, proxy, IDS/IPS).
9. **Auditar uso interno** – Caso a sua rede possua comunicação legítima com a VULTR, validar se há necessidade real dessa conexão. Caso contrário, interromper.

---

### Considerações Finais
O endereço **216.238.109.50** apresenta múltiplos indícios de **uso malicioso**: hospedagem de domínios de phishing de curta vida, exposição de serviços de VPN e SSH sem restrição, e ausência de vulnerabilidades específicas divulgadas, porém com software desatualizado. A combinação destes fatores o classifica como **alto risco** para ser usado como infraestrutura de ataque ou para enganar usuários finais. A adoção das recomendações acima permite identificar, conter e mitigar possíveis impactos associados a este IP.