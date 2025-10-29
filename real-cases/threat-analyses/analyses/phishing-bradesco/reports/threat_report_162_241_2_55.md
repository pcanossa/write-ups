# Relatório de Threat Intelligence – IP **162.241.2.55**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io (sem resultados relevantes).  
> **Última coleta Shodan**: 2025‑10‑17.  

---

## 1. Resumo Executivo  

- **Localização**: EUA – Provo/UT (ARIN) / Atlanta/GA (IPInfo).  
- **ASN / ISP**: AS19871 – *Network Solutions, LLC* (operado por **Unified Layer**).  
- **Serviços expostos**: 22 portas TCP, dentre elas serviços de administração remota (SSH, cPanel/WHM), bases de dados (MySQL), servidores de e‑mail (Exim, Dovecot) e FTP público.  
- **Indicadores de comportamento suspeito**: o endereço IP hospeda centenas de domínios **phishing** e sites de “landing pages” que redirecionam para blogs legítimos (ex.: `blog.veroo.com.br`). Vários dos domínios apontam para a mesma página de “Hospedagem de Site com Domínio Grátis – HostGator”, sugestão de uso de hosting barato para abuso.  
- **Vulnerabilidades conhecidas**: versões antigas de OpenSSH 7.4 e Exim 4.98.1 apresentam diversas CVEs com severidade de **Critical a High** (ex.: CVE‑2025‑32728, CVE‑2025‑30232).  

**Conclusão**: o IP está sendo usado como *hosting de baixo custo* para múltiplos sites, inclusive de phishing, e oferece vários serviços de administração expostos que apresentam vulnerabilidades críticas. É altamente provável que o ator malicioso explore a combinação de serviços legados e credenciais fracas para conduzir **ataques de força‑bruta, exploração de CVE e coleta de credenciais**.

---

## 2. Análise de Comportamento  

| Evidência | Interpretação |
|-----------|---------------|
| **Tag “database”, “eol‑product”, “starttls”** (Shodan) | Indica que o host executa serviços de banco de dados (MySQL) e servidores de e‑mail que suportam STARTTLS, porém alguns destes produtos estão em fim de vida. |
| **Serviços de e‑mail** (Exim 4.98.1 nas portas 26, 465, 587) | Versão vulnerável a uso‑after‑free (CVE‑2025‑30232) que pode permitir elevação de privilégio a usuários com acesso à linha de comando. |
| **SSH 7.4** (portas 22 e 2222) | Várias CVEs críticas (ex.: CVE‑2025‑32728, CVE‑2025‑26465) que podem ser exploradas para bypass de autenticação ou ataque de Row‑Hammer. |
| **Pure‑FTPd** (porta 21) | Serviço FTP aberto, sem indícios de restrição de acesso; possibilidade de login anônimo ou credenciais fracas. |
| **cPanel/WHM** (portas 2082‑2087) | Interfaces de administração de hospedagem web (login “cPanel”) expostas ao público; alvo clássico de força‑bruta e exploração de vulnerabilidades de plugins. |
| **MySQL 5.7.23** (porta 3306) | Versão ainda suportada, porém pode ser alvo de bruteforce se não estiver adequadamente protegida. |
| **Múltiplos domínios phishing** (URLScan) | O IP serve como “forwarder” ou página de captura para domínios suspeitos (ex.: `bradescard-americanblackexclusivo.com`, `blackconviteplus.com`). Muitas dessas URLs apontam para o mesmo conteúdo de blog, sugerindo uso de *cloaking* ou *link‑bait*. |
| **Certificados SSL** | Todos emitidos por **Sectigo** com validade de 1 ano (2025‑2026). Não há indícios de comprometimento na cadeia, mas a presença de HTTPS não impede abuso de conteúdo. |
| **Abuse contacts** (ARIN) | EIG‑Abuse Mitigation (email `IARPOC@Newfold.com`) e NOC da Unified Layer (email `abuse@bluehost.com`). Estes contatos podem ser acionados para reporte de abuso. |

**Padrão de uso**: o IP funciona como um *multi‑tenant* de hospedagem barata (possivelmente ambiente **cPanel/WHM** compartilhado). Atacantes aproveitam a baixa fricção de criação de contas para hospedar páginas de phishing ou redirecionamentos maliciosos, enquanto tiram proveito de serviços de gerenciamento (SSH, FTP) que permanecem abertos e desatualizados.

---

## 3. Superfície de Ataque  

### 3.1 Portas abertas & serviços

| Porta | Serviço | Versão / Produto | Observações |
|------|---------|------------------|-------------|
| 21   | **Pure‑FTPd** | `Pure-FTPd 1.0.49` (TLS) | Permitido login anônimo? |
| 22   | **OpenSSH** | 7.4 | CVEs críticas (CVE‑2025‑32728, CVE‑2025‑26465, etc.) |
| 26   | **Exim smtpd** | 4.98.1 | Use‑after‑free (CVE‑2025‑30232) |
| 53   | **DNS** (BIND/ISC) | 9.11.4‑P2‑RedHat | Normal |
| 80   | **Apache httpd** | 2.4.x | Servindo página padrão HostGator |
| 110  | **Dovecot POP3** | 2.x | TLS suportado |
| 143  | **Dovecot IMAP** | 2.x | TLS suportado |
| 2082 | **cPanel (HTTP)** |  | Login cPanel (sem TLS) |
| 2083 | **cPanel (HTTPS)** |  | Login cPanel (TLS) |
| 2086 | **WHM (HTTP)** |  | Login WHM (sem TLS) |
| 2087 | **WHM (HTTPS)** |  | Redirecionamento para host “br904.hostgator.com.br” |
| 2095 | **Webmail** (Roundcube) |  | Login webmail |
| 2222 | **OpenSSH** (alternativa) | 7.4 | Similar à porta 22 |
| 3306 | **MySQL** | 5.7.23‑23 | Autenticação `mysql_native_password` |
| 465  | **Exim (TLS)** | 4.98.1 | CVE‑2025‑30232 (high) |
| 587  | **Exim (STARTTLS)** | 4.98.1 | CVE‑2025‑30232 (high) |
| 993  | **Dovecot IMAPS** | 2.x | TLS |
| 995  | **Dovecot POP3S** | 2.x | TLS |

### 3.2 Vulnerabilidades (CVEs) identificadas

| CVE | Severidade* | Produto | Resumo |
|-----|------------|--------|--------|
| **CVE‑2025‑32728** | Critical | OpenSSH ≤ 9.9 | `DisableForwarding` não impede X11/agent forwarding. |
| **CVE‑2025‑30232** | High | Exim 4.96‑4.98.1 | Uso‑after‑free → elevação de privilégio para usuários de linha de comando. |
| **CVE‑2025‑26465** | High | OpenSSH ≤ 9.9 | Possibilidade de ataque *memory‑exhaustion* quando `VerifyHostKeyDNS` está habilitado. |
| **CVE‑2023‑51767** | High | OpenSSH ≤ 10.0 | Possível *row‑hammer* para bypass de autenticação (requer co‑location). |
| **CVE‑2023‑51385** | Medium | OpenSSH ≤ 9.6 | Injeção de comandos ao usar nomes de usuário/host com metacaracteres. |
| **CVE‑2023‑48795** | Medium | OpenSSH (extensions) | “Terrapin attack” – bypass de integridade da conexão SSH. |
| **CVE‑2023‑38408** | Critical | OpenSSH (PKCS#11) | Execução remota de código via caminho de biblioteca não confiável. |
| **CVE‑2021‑41617** | High | OpenSSH ≤ 8.8 | Escalada de privilégio via `AuthorizedKeysCommand` quando executado como outro usuário. |
| **CVE‑2021‑36368** | Low | OpenSSH ≤ 8.9 | Possível confusão de autenticação FIDO/SSH. |
| **CVE‑2020‑15778** | High | OpenSSH ≤ 8.3p1 | Injeção de comandos via argumento `scp`. |
| **CVE‑2020‑14145** | Medium | OpenSSH ≤ 8.4 | Vazamento de informações via algoritmo de negociação. |
| **CVE‑2019‑6111** | Medium | OpenSSH 7.9 | Manipulação de nomes de arquivo via servidor `scp` malicioso. |
| **CVE‑2019‑6110** | High | OpenSSH 7.9 | Manipulação de saída `stderr` permite esconder arquivos. |
| **CVE‑2019‑6109** | High | OpenSSH 7.9 | Uso de códigos de controle ANSI para esconder dados. |
| **CVE‑2018‑20685** | Medium | OpenSSH 7.9 | Bypass de restrições via nome de arquivo `.` ou vazio. |
| **CVE‑2018‑15919** | Medium | OpenSSH ≤ 7.8 | Enumeração de usuários via GSSAPI. |
| **CVE‑2018‑15473** | Medium | OpenSSH ≤ 7.7 | Enumeração de usuários por tempo de resposta. |
| **CVE‑2017‑15906** | Medium | OpenSSH ≤ 7.6 | Criação de arquivos zero‑byte via `sftp-server`. |
| **CVE‑2016‑20012** | Medium | OpenSSH ≤ 8.7 | Enumerar usuários/keys via `sshd`. |
| **CVE‑2008‑3844** | Critical | OpenSSH (RedHat 4/5) | Trojan inserido em pacotes “signed” – fora de escopo aqui. |
| **CVE‑2007‑2768** | Medium | OpenSSH (OPIE) | Enumeração de usuários OPIE. |

\*Classificação baseada no *CVSS* presente nos dados Shodan (Critical = 9‑10, High = 7‑8.9, Medium = 4‑6.9, Low = 0‑3.9).

---

## 4. Informações de Rede e Geográficas  

| Campo | Valor |
|-------|-------|
| **IP** | 162.241.2.55 |
| **Hostname** | `162-241-2-55.unifiedlayer.com` |
| **ASN** | AS19871 |
| **Organização** | *Network Solutions, LLC* – operado por **Unified Layer** (HostGator/Bluehost). |
| **País** | United States |
| **Região / Cidade** | Provo, Utah (ARIN) / Atlanta, Georgia (IPInfo) – discrepância típica de data‑center. |
| **ISP** | Network Solutions, LLC |
| **Bloco CIDR** | 162.240.0.0/15 |
| **Data de registro do bloco** | 22 ago 2013 |
| **Data da última atualização** | 22 set 2025 |
| **Contatos de abuso** | `IARPOC@Newfold.com` (EIG‑Abuse), `abuse@bluehost.com` (NOC), telefone +1‑801‑765‑9400. |
| **Tipo de rede** | Direct Allocation (não transitória). |

---

## 5. Recomendações de Investigação & Mitigação (Próximos passos)

1. **Bloqueio de portas de gerenciamento**  
   - Imediatamente bloquear inbound nas portas **22 / 2222 (SSH)**, **2082‑2087 (cPanel/WHM)** e **3306 (MySQL)** se não houver necessidade explícita.  
   - Restringir o acesso a **FTP (21)** a IPs confiáveis ou desativá‑lo.

2. **Hardening de serviços**  
   - Atualizar **OpenSSH** para ≥ 9.8 (corrige CVE‑2025‑32728, 38408, 26465).  
   - Atualizar **Exim** para versão ≥ 4.99 (corrige CVE‑2025‑30232).  
   - Desabilitar **login anônimo** no Pure‑FTPd ou remover o serviço.  
   - Reforçar a política de senhas e habilitar **autenticação por chave pública** no SSH.  

3. **Monitoramento de logs**  
   - Coletar e analisar logs de autenticação SSH, FTP, MySQL e web (cPanel).  
   - Procurar tentativas de brute‑force, comando “sudo” inesperado ou uploads de arquivos suspeitos.  

4. **Varredura de malware**  
   - Executar anti‑malware no filesystem do servidor (ex.: ClamAV, Malwarebytes) para detectar possíveis scripts de phishing ou webshells.  

5. **Revisão de aplicações web**  
   - Verificar vulnerabilidades de **cPanel/WHM plugins**, **Roundcube**, **Dovecot/Exim** (ex.: permissões de arquivos, scripts PHP desatualizados).  
   - Aplicar **WAF** (Web Application Firewall) ou regras de bloqueio baseadas em URI (ex.: `/login`, `/admin`).  

6. **Relatório e comunicação**  
   - Notificar os provedores de abuso (EIG‑Abuse, Bluehost) com evidências de uso de phishing.  
   - Marcar os domínios listados nas análises de URLScan como “phishing” nos sistemas de filtragem de e‑mail e DNS (ex.: SURBL, Google Safe Browsing).  

7. **Inteligência adicional**  
   - Consultar bases de dados de phishing (PhishTank, OpenPhish) para correlacionar novos domínios associados ao IP.  
   - Verificar se o IP aparece em listas de “malicious IP” (Spamhaus, AbuseIPDB) e, se necessário, aplicar *blocklist* em firewalls corporativos.  

---

**Nota**: Este relatório concentra‑se na identificação de riscos e nas ações de investigação. As recomendações de mitigação não detalham *como* aplicar patches ou configurações específicas, pois o foco é orientar a equipe de segurança na priorização de respostas.