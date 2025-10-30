# Relatório de Threat Intelligence – IP **162.241.2.55**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN/WHOIS, RDAP, URLScan.io.  
> **Última coleta Shodan**: 2025‑10‑29 (dados exportados diretamente da página do host).  

---

## 1. Resumo Executivo
O endereço **162.241.2.55** pertence ao bloco de rede da **Unified Layer** (AS19871 – Network Solutions, LLC) e está localizado nos **Estados Unidos (Georgia – região de Atlanta)**. O servidor hospeda múltiplos serviços públicos (FTP, SSH, SMTP, IMAP, MySQL, HTTP/HTTPS) e, sobretudo, serve como **shared‑hosting** para centenas de domínios (blog.veroo.com.br, e‑energiasolar.com.br, múltiplos sub‑domains de “*.hostgator.com.br”).  

Diversos relatórios de URLScan.io apontam que esse IP tem sido usado como *hosting* para domínios classificados como **suspeitos ou phishing** (ex.: “blackconviteexclusivo.com”, “vipblackconvite.com”, “regularizandocpf.com”, etc.). As páginas retornam conteúdo legítimo (p.ex. blogs) ou páginas de erro 403/404, mas o padrão de redirecionamento para o mesmo blog indica uso de **infrastructure abuse** (portais de spam/phishing redirecionando tráfego para um site popular).

Os serviços expostos apresentam vulnerabilidades conhecidas:
- **OpenSSH 7.4** (port 22) – várias CVEs (ex.: CVE‑2025‑32728, CVE‑2025‑26465, CVE‑2023‑51767, CVE‑2023‑38408, etc.) – risco de escalonamento de privilégio, bypass de autenticação e execução de código via SSH.
- **Exim 4.98.1** (port 26/465/587) – CVE‑2025‑30232 (use‑after‑free) – permite elevação de privilégio para usuários com acesso à linha de comando.
- **MySQL 5.7.23‑23** (port 3306) – vulnerabilidades conhecidas de execução remota de código por autenticação fraca ou configuração incorreta (não listadas explicitamente, mas a versão já está fora de suporte).

Essas falhas, combinadas com a exposição pública de serviços críticos, aumentam a probabilidade de **comprometimento do servidor** e de **uso como pivô** para ataques a domínios hospedados.

---

## 2. Análise de Comportamento

| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Portas abertas** | 21, 22, 26, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2082‑2087, 2095, 2222, 3306 | Serviços de FTP, SSH, DNS, HTTP/HTTPS, SMTP (com STARTTLS), IMAP/POP3, cPanel/WHM, MySQL – tipicamente expostos por servidores de hospedagem compartilhada. |
| **Serviços identificados** | Pure‑FTPd, OpenSSH 7.4, Exim 4.98.1, Dovecot (IMAP), Apache httpd, MySQL 5.7 | Versões antigas e/ou não mantidas, vulneráveis a exploits conhecidos. |
| **Certificado TLS** | *.hostgator.com.br, emitido por Sectigo (valido até 2026‑06‑03) | Indica que o host entrega conteúdo de clientes HostGator (cPanel/WHM). |
| **Domínios associados** | hostgator.com.br, blog.veroo.com.br, e‑energiasolar.com.br, diverse “blackconvite*”, “regulariza*”, etc. | Uso como **shared hosting**; presença de domínios suspeitos/phishing. |
| **Resultados do URLScan.io** | > 150 variações de scans em 30 dias, várias marcadas como **suspect**, **phish_report**, **falconsandbox**, **phishtank** | Indica que o IP tem sido usado para servir ou redirecionar tráfego mal‑icioso. A maioria dos scans apontam para o mesmo blog (veroo.com.br) como destino final, típico de camadas de “landing page” de campanhas de phishing. |
| **Vulnerabilidades OpenSSH** | CVE‑2025‑32728, CVE‑2025‑26465, CVE‑2023‑51767, CVE‑2023‑38408, CVE‑2020‑15778, etc. (2‑5 CVEs críticas) | Permitem bypass de X11/agent forwarding, escalonamento de privilégio, ataque de row‑hammer, MITM em handshake, execução remota via comando mal‑formado. |
| **Vulnerabilidade Exim** | CVE‑2025‑30232 (use‑after‑free) – alta severidade (CVSS 8.1) | Usuário com acesso ao shell pode ganhar privilégios de root; risco de comprometimento total do host. |
| **Logs de firewall** | Não fornecidos, mas a presença de portas não‑necessárias (2222 – porta alternativa de SSH, 26 – SMTP sem TLS padrão) sugere superfície de ataque ampla. | |

**Conclusão comportamental:**  
O IP funciona como um servidor de hospedagem multi‑tenant (cPanel/WHM). A presença de serviços legados vulneráveis (OpenSSH 7.4, Exim 4.98.1) e a ampla lista de domínios, incluindo muitos identificados como phishing, indicam que o host pode estar **comprometido ou sendo usado deliberadamente para hospedagem de conteúdo mal‑icioso**. O tráfego redirecionado a um domínio legítimo (veroo.com.br) pode ser utilizado para camuflagem (técnica de *domain‑fronting* ou *link‑baiting*).  

---

## 3. Superfície de Ataque

### 3.1. Portas e Serviços
| Porta | Serviço | Versão | Comentários |
|------|---------|--------|-------------|
| 21 | **Pure‑FTPd** | 1.0.49 (exibe banner) | Permite login anônimo; sem TLS explícito. |
| 22 | **OpenSSH** | 7.4p1 | Vulnerável a várias CVEs (listadas abaixo). |
| 26 | **Exim SMTP** | 4.98.1 | Uso não‑padrão, mas funcional; vulnerável a CVE‑2025‑30232. |
| 53 (TCP/UDP) | **BIND/DNS** | 9.11.4‑P2 (RHEL) | Serviço visível; pode ser usado para amplificação. |
| 80 | **Apache httpd** | 2.4 (versão não especificada) | Servidor web padrão; usado para redirecionamentos. |
| 110 | **Dovecot POP3** | (versão implícita) | Autenticação STARTTLS. |
| 143 | **Dovecot IMAP** | (versão implícita) | Autenticação STARTTLS. |
| 443 | **Apache https** | (versão implícita) | TLS certificado *.hostgator.com.br. |
| 465 | **Exim SMTPS** | 4.98.1 | Vulnerável a CVE‑2025‑30232 (high). |
| 587 | **Exim Submission** | 4.98.1 | STARTTLS; mesma vulnerabilidade. |
| 993 | **Dovecot IMAPS** | (versão implícita) | |
| 995 | **Dovecot POP3S** | (versão implícita) | |
| 2082‑2087 | **cPanel/WHM** | (cPanel 86‑? / WHM 86‑?) | Portas de gerenciamento (cPanel 2082/2083, WHM 2086/2087). |
| 2095 | **Webmail** | (Roundcube) | Interface webmail pública. |
| 2222 | **OpenSSH (alternate)** | 7.4p1 | Porta alternativa para SSH. |
| 3306 | **MySQL** | 5.7.23‑23 | Versão fora de suporte, vulnerável a vários exploits. |

### 3.2. Vulnerabilidades (CVE) associadas (Shodan)

| Porta | CVE | Severidade (CVSS) | Impacto |
|------|-----|-------------------|---------|
| 22 (OpenSSH 7.4) | **CVE‑2025‑32728** | 4.3 (Medium) | `DisableForwarding` não funciona como documentado – pode ser usado para desabilitar X11/agent forwarding. |
| 22 | **CVE‑2025‑26465** | 6.8 (High) | Use‑after‑free quando `VerifyHostKeyDNS` está habilitado – potencialmente permite escalonamento de privilégio via memória. |
| 22 | **CVE‑2023‑51767** | 7.0 (High) | Row‑hammer ataque (requere co‑localização). |
| 22 | **CVE‑2023‑38408** | 9.8 (Critical) | Execução remota de código via PKCS#11 path ao encaminhar agente SSH. |
| 22 | **CVE‑2020‑15778** | 7.4 (High) | Injeção de comando no `scp` (backticks no destino). |
| 26/465/587 (Exim 4.98.1) | **CVE‑2025‑30232** | 8.1 (Critical) | Use‑after‑free que pode levar a elevação de privilégio para usuários shell. |
| 22/26/465/587 | **CVE‑2021‑41617**, **CVE‑2021‑36368**, **CVE‑2020‑14145**, **CVE‑2019‑6109/61010/6111**, **CVE‑2018‑20685**, **CVE‑2018‑15473**, **CVE‑2018‑15919**, **CVE‑2017‑15906**, **CVE‑2016‑20012** | Várias (low‑high) | Diversos vetores (enumerar usuários, bypass de autenticação, MITM, etc.). |
| 3306 (MySQL 5.7) | Vários CVEs de `caching_sha2_password`, `root` credential leakage, `SQL injection` via mis‑config. | Medium‑High | Pode permitir acesso remoto ao banco de dados se credenciais fracas. |

> **Observação:** Muitas dessas vulnerabilidades são *potenciais*; a exploração depende de credenciais ou de configuração específica. Contudo, a presença de versões antigas torna o risco real.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|------|-------|
| **ASN** | **AS19871** – *Network Solutions, LLC* (também listado como **AS46606 – Unified Layer** em alguns relatórios). |
| **Organização** | *Unified Layer* (provedor de serviços de hospedagem, parte da HostGator). |
| **ISP** | *Network Solutions, LLC* (também referenciado como **Network‑Solutions‑Hosting**). |
| **Localização** | **Estados Unidos – Georgia** (cidades: *Atlanta* (IPInfo) e *Provo, UT* (Shodan) – discrepância provável por localização de roteamento). |
| **Bloco CIDR** | 162.240.0.0/15 (NET‑162‑240‑0‑0‑1). |
| **Registros RDAP** | Nome da organização: **Unified Layer** – endereço: 1958 South 950 East, Provo, UT 84606, EUA. |
| **PTR** | `162-241-2-55.unifiedlayer.com`. |
| **Data de registro** | 22 / 08 / 2013 (última atualização 22 / 09 / 2025). |

---

## 5. Recomendações de Investigação e Mitigação

1. **Coleta de logs internos**
   - Solicite ao provedor (Unified Layer/HostGator) os logs de firewall, SSH, SMTP e MySQL para o intervalo dos últimos 30‑45 dias.
   - Verifique tentativas de login bem‑sucedidas/falhas nos serviços vulneráveis (SSH 22/2222, Exim 26/465/587, MySQL 3306).

2. **Validação de credenciais**
   - Teste a força das senhas de contas de administração (cPanel/WHM) usando ferramentas de auditoria interna (não brute‑force externo). Caso haja credenciais fracas, o atacante pode obter controle total.

3. **Patch/Upgrade de serviços**
   - **OpenSSH**: atualizar imediatamente para ≥ 8.9p1 (ou a versão mais recente suportada pela hospedagem).  
   - **Exim**: atualizar para a versão mais recente (≥ 4.99) que corrige CVE‑2025‑30232.  
   - **MySQL**: migrar para uma versão suportada (≥ 8.0) ou, no mínimo, aplicar patches críticos.  
   - **Pure‑FTPd** e **Dovecot**: garantir configuração segura (desabilitar login anônimo, exigir TLS).

4. **Hardening de serviços**
   - Desabilitar a porta **26** (SMTP não‑padrão) e **2222** (SSH alternativo) se não forem necessárias.  
   - Restringir acesso ao **cPanel/WHM** (2082‑2087) a IPs de administração confiáveis via firewall ou VPN.  
   - Configurar **fail2ban** ou equivalente para bloquear tentativas repetidas de login em SSH/FTP/SMTP.  
   - Aplicar **HSTS** e políticas de segurança de cabeçalho HTTP (X‑Content‑Type‑Options, X‑Frame‑Options, CSP) nos sites hospedados.

5. **Monitoramento de Abuse**
   - Inserir o IP/ASN em listas de monitoramento interno (SIEM) para alertas de tráfego incomum (ex.: volume alto de e‑mail enviado, conexões SSH de países fora da América do Norte).  
   - Submeter o IP ao **AbuseIPDB**, **Spamhaus**, **PhishTank** para registro de abuso e receber atualizações de classificação.

6. **Análise de Domínios Maliciosos**
   - Verificar a reputação de todos os domínios apontados nos resultados de URLScan (ex.: “blackconviteexclusivo.com”, “regularizandocpf.com”) e solicitar remoção ou bloqueio ao registrador se confirmados como phishing.  
   - Avaliar se algum desses domínios está apontando registros **CNAME** para o mesmo IP (indicativo de uso de “wildcard hosting” para phishing em massa).

7. **Resposta a Incidentes**
   - Caso se confirme comprometimento, isolar o servidor (desativar temporariamente os serviços externos) e coletar uma **imagem forense** completa.  
   - Revisar scripts, crontabs e possíveis backdoors instalados (ex.: arquivos `.php` desconhecidos, webshells).  
   - Re‑gerar certificados TLS para os domínios afetados ou migrar para **Let's Encrypt** com renovação automática.

---

## 6. Conclusão

O IP **162.241.2.55** funciona como um servidor de hospedagem compartilhada que expõe uma ampla gama de serviços, muitos deles com versões vulneráveis a CVEs críticos. O registro de inúmeros domínios suspeitos (phishing, scams) que utilizam este host, aliado às vulnerabilidades conhecidas em OpenSSH e Exim, indica alta probabilidade de que o endereço esteja sendo **abusado como infraestrutura de campanha maliciosa**.  

A recomendação principal é a **imediata atualização/patch** dos serviços vulneráveis, reforço da política de acesso (firewall, MFA), coleta de logs para evidência de abuso e monitoramento contínuo do IP/ASN em bases de dados de ameaças. Caso a organização responsável (Unified Layer/HostGator) não atue rapidamente, o IP permanecerá um ponto de pivô para atores maliciosos, ameaçando a reputação dos domínios legítimos hospedados nele.