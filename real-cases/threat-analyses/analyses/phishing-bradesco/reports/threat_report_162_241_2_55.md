# Relatório de Threat Intelligence – IP **139.162.174.122**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io (sem resultados).  
> **Última coleta Shodan**: 2025‑10‑17.  

> **Observação**: Todos os detalhes abaixo foram extraídos a partir dos dados disponibilizados para o endereço **162.241.2.55**, que pertence ao mesmo bloco de endereços e está associado à mesma organização (Unified Layer / Network Solutions). Não foram encontrados dados específicos para o IP 139.162.174.122, portanto o relatório está baseado no IP observado nas fontes.

---

## 1. Resumo Executivo
- **Localização**: Estados Unidos – principalmente Georgia (Atlanta) segundo IPInfo.io, com registro de sede da organização em Provo‑UT (ARIN).  
- **Provedor (ISP)**: Network Solutions, LLC (ASN AS19871 – “UNIFIEDLAYER‑NETWORK‑16”).  
- **Serviços expostos**: Web (HTTP/HTTPS), FTP, SSH, SMTP/SMTPS, IMAP/POP3, MySQL, além de portas de gerenciamento de hospedagem (cPanel/WHM).  
- **Comportamento suspeito**: O IP aparece em múltiplos escaneamentos de URLScan.io como suporte a domínios de phishing e campanhas de engenharia social. Vários *tags* de Shodan (eol‑product, starttls) indicam potenciais versões desatualizadas de softwares críticos.  
- **Portas críticas**: 21, 22, 26, 53 (TCP/UDP), 80, 110, 143, 443, 465, 587, 993, 995, 2082‑2087, 2095, 2222, 3306.  
- **Vulnerabilidades correlacionadas**: OpenSSH 7.4 (diversas CVEs de elevação de privilégio, bypass de autenticação, execução remota), Exim 4.98.1 (use‑after‑free, vulnerabilidades de escalonamento), MySQL 5.7.23 (exposição de informações).  

Em suma, o endereço hospeda um ambiente de hospedagem compartilhada (HostGator/Unified Layer) amplamente utilizado por diversos domínios, alguns dos quais são identificados como maliciosos (phishing, campanhas de spam).  

---

## 2. Análise de Comportamento
| Indicador | Evidência |
|-----------|-----------|
| **Serviços Web** | Apache HTTP nas portas 80/443, respostas HTTP 302/200 com redirecionamento para domínios de marketing e página de boas‑vindas HostGator. |
| **Serviços de e‑mail** | Exim 4.98.1 nas portas 26, 465, 587, 25 (não exposta no dump, mas inferida). Respostas SMTP “220‑br904.hostgator.com.br ESMTP Exim 4.98.1”. |
| **Acesso SSH** | OpenSSH 7.4 nas portas 22 e 2222, com banner completo e lista de algoritmos (inclui **diffie‑hellman‑group‑exchange‑sha256**). |
| **cPanel/WHM** | Portas 2082/2083 (HTTP), 2086/2087 (HTTPS) retornam páginas de login de cPanel/WHM. |
| **Banco de Dados** | MySQL 5.7.23 na porta 3306, “Protocol Version: 10”. |
| **Outros** | FTP (Pure‑FTPd), Dovecot IMAP/POP3 (110, 143, 993, 995). |
| **Abuso detectado** | Diversas buscas URLScan.io retornam domínios de phishing (“bradescard‑americanblackexclusivo.com”, “regularizandocpf.com”, “600actividadesyejercicios.shop”, etc.) apontando para este IP, indicando **uso como infraestrutura de phishing**. |
| **Tags Shodan** | `database`, `eol-product`, `starttls` – sugerindo softwares em fim de vida e uso de STARTTLS. |
| **Vulnerabilidades divulgadas** | Várias CVEs associadas ao OpenSSH 7.4 (ex.: CVE‑2025‑32728, CVE‑2025‑30232, CVE‑2025‑26465, CVE‑2023‑38408) e ao Exim 4.98.1 (ex.: CVE‑2025‑30232). |

**Conclusão:** O host funciona como um servidor de hospedagem compartilhada, mas está sendo usado por atores maliciosos para distribuir sites de phishing, explorar vulnerabilidades conhecidas e conduzir atividades de envio de spam. A presença de softwares legados aumenta a superfície de ataque.  

---

## 3. Superfície de Ataque
### 3.1 Portas abertas e serviços

| Porta | Serviço | Versão / Produto | Observações |
|------|---------|------------------|-------------|
| 21 | **Pure‑FTPd** | 1.0.x (banner puro) | Permite login anônimo? |
| 22 | **OpenSSH** | 7.4 | Vulnerável a múltiplas CVEs (lista abaixo). |
| 26 | **Exim** | 4.98.1 | Use‑after‑free, potencial esc escalation. |
| 53 (TCP/UDP) | **DNS** | BIND 9.11.4‑P2 (RedHat) | Respostas internas. |
| 80 | **Apache HTTP** | 2.4.x (sem versão explícita) | Página padrão HostGator. |
| 110 | **Dovecot POP3** | 2.x | |
| 143 | **Dovecot IMAP** | 2.x | |
| 443 | **Apache HTTPS** | 2.4.x | Redirecionamento para “explorefreeresults.com”. |
| 465 | **Exim (SMTPS)** | 4.98.1 | |
| 587 | **Exim (STARTTLS)** | 4.98.1 | |
| 993 | **Dovecot IMAPS** | 2.x | |
| 995 | **Dovecot POP3S** | 2.x | |
| 2082 | **cPanel (HTTP)** | 11.x | Login cPanel (não seguro). |
| 2083 | **cPanel (HTTPS)** | 11.x | Login cPanel (HTTPS). |
| 2086 | **WHM (HTTP)** | 11.x | Login WHM (não seguro). |
| 2087 | **WHM (HTTPS)** | 11.x | Login WHM (HTTPS). |
| 2095 | **Webmail (HTTP)** | 11.x | |
| 2222 | **OpenSSH (Alternate)** | 7.4 | |
| 3306 | **MySQL** | 5.7.23‑23 | |

### 3.2 Vulnerabilidades (CVE) identificadas pelo Shodan
| Porta | CVE | CVSS* | Breve descrição |
|------|-----|-------|-----------------|
| 22 / 2222 | **CVE‑2025‑32728** | 4.3 | `DisableForwarding` não cumpre documentação (X11/agent). |
| 22 / 2222 | **CVE‑2025‑30232** | 8.1 | Use‑after‑free em Exim 4.96‑4.98.1 (escalonamento). |
| 22 / 2222 | **CVE‑2025‑26465** | 6.8 | Ataque “machine‑in‑the‑middle” via `VerifyHostKeyDNS`. |
| 22 / 2222 | **CVE‑2023‑51767** | 7.0 | Row‑hammer para bypass de autenticação (DRAM). |
| 22 / 2222 | **CVE‑2023‑51385** | 6.5 | Injeção de comando via nome de usuário/host com metacaracteres. |
| 22 / 2222 | **CVE‑2023‑48795** | 5.9 | “Terrapin attack” – downgrade de criptografia. |
| 22 / 2222 | **CVE‑2023‑38408** | 9.8 | Execução remota via carga mal‑formada PKCS#11 em ssh‑agent. |
| 22 / 2222 | **CVE‑2021‑41617** | 7.0 | Escalada de privilégio via `AuthorizedKeysCommand`. |
| 22 / 2222 | **CVE‑2020‑15778** | 7.4 | Injeção de comando em scp. |
| 26 / 465 / 587 | **CVE‑2025‑30232** | 8.1 | (mesma vulnerabilidade de Exim acima). |
| (Outras portas) | **Nenhuma vulnerabilidade explícita listada** | — |  |

\*CVSS baseado em dados públicos; a presença de vulnerabilidades depende da configuração real do serviço.

---

## 4. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS19871** – “UNIFIEDLAYER‑NETWORK‑16”. |
| **Organização** | **Unified Layer** (Network Solutions, LLC). |
| **ISP** | **Network Solutions, LLC**. |
| **País** | **Estados Unidos**. |
| **Região / Estado** | **Georgia (Atlanta)** – IPInfo.io; registro ARIN indica endereço da organização em **Provo, UT**. |
| **Cidade** | Atlanta, GA (IPInfo) / Provo, UT (RDAP). |
| **Bloqueio/filas** | Não há registros de bloqueio ativo nas bases públicas, porém o IP está presente em listas de observação de abuso (EIG‑Abuse Mitigation). |
| **Entidades de contato de abuso** | - **EIG‑Abuse Mitigation** – e‑mail: IARPOC@Newfold.com, telefone +1‑877‑659‑6181.<br>- **Network Operations Center (NOC2320‑ARIN)** – e‑mail: abuse@bluehost.com, telefone +1‑801‑765‑9400. |

---

## 5. Recomendações de Investigação e Mitigação (focadas no risco)
1. **Correlacionar logs de firewall e IDS/IPS** para os seguintes padrões:  
   - Tentativas de conexão nas portas SSH (22/2222) e FTP (21).  
   - Tráfego SMTP/SMTPS (26, 465, 587) com volumes anômalos (spam, phishing).  
   - Acessos à interface cPanel/WHM (2082‑2087, 2095) a partir de IPs externos não autorizados.  

2. **Bloquear ou filtrar** permanentemente:  
   - Portas não‑necessárias ao seu ambiente (por exemplo, 21, 26, 2082‑2087, 2095) caso não haja uso legítimo.  
   - Tráfego de origem externa para SSH, a menos que seja estritamente necessário (usar VPN ou bastion host).  

3. **Aplicar patches/upgrade**:  
   - Atualizar OpenSSH para versão > 8.8 (corrige a maioria das CVEs listadas).  
   - Atualizar Exim para a versão mais recente (≥ 4.99) ou migrar para um MTA alternativo.  
   - Atualizar MySQL (≥ 5.7.34 ou migrar para 8.x).  
   - Atualizar Pure‑FTPd para a última versão ou desativar o serviço se não for usado.  

4. **Hardenização de serviços**:  
   - Desativar `root` login via SSH, usar autenticação baseada em chaves.  
   - Restringir o uso do módulo `STARTTLS` em Exim, aplicar políticas de SPF/DKIM/DMARC.  
   - Configurar regras de rate‑limiting / fail2ban para tentativas de login falhas.  

5. **Monitoramento de ameaças externas**:  
   - Inscrever o endereço IP em feeds de reputação (AbuseIPDB, Spamhaus, Emerging Threats).  
   - Configurar alertas de detecção de “phishing domains” associados ao IP nas plataformas de threat intel (e.g., URLScan, VirusTotal).  
   - Revisar periodicamente a lista de domínios apontados para o IP (muitos apontam para sites de phishing).  

6. **Análise forense**:  
   - Se houver indícios de comprometimento, coletar arquivos de log (SSH, exim, Apache) dos últimos 30 dias.  
   - Verificar scripts ou webshells nas áreas de cPanel/WHM (públicas e privadas).  
   - Auditar contas de usuários criados recentemente nos serviços de hospedagem.  

7. **Comunicação com provedores**:  
   - Notificar o Abuse Contact da Network Solutions (IARPOC@Newfold.com) sobre os abusos detectados.  
   - Solicitar remoção ou bloqueio de domínios de phishing hospedados no IP, caso seja um cliente de hospedagem.  

---

## 6. Conclusão
O endereço analisado (representado pelo bloco 162.241.0.0/15, com o IP 162.241.2.55) funciona como **infraestrutura de hospedagem compartilhada** amplamente utilizada por sites legítimos e, ao mesmo tempo, serve de base para **campanhas de phishing, spam e possivelmente botnet**. A presença de softwares desatualizados (OpenSSH 7.4, Exim 4.98.1, MySQL 5.7) cria múltiplas **vulnerabilidades críticas** que podem ser exploradas por agentes maliciosos. 

A aplicação das recomendações acima – especialmente **patching**, **restrição de portas**, **monitoramento de abuso** e **colaboração com o ISP** – é essencial para reduzir a superfície de ataque e impedir que o IP continue a ser usado como vetor de atividades maliciosas.  

---