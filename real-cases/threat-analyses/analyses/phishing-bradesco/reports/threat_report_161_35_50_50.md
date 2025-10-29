# Relatório de Threat Intelligence – IP **161.35.50.50**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN / RDAP, URLScan.io.  
> **Última coleta Shodan**: 2025‑10‑27  

---

## 1. Resumo Executivo
O endereço **161.35.50.50** pertence à nuvem da **DigitalOcean (AS14061)** e está localizado em **North Bergen, New Jersey, EUA**. O host apresenta os serviços **OpenSSH 9.6p1** (porta 22) e **Apache httpd 2.4.58** (portas 80 / 443) que, segundo o Shodan, sofrem de **várias vulnerabilidades (4 críticas, 17 altas, 9 médias e 2 baixas)**. Não há indícios claros de atividade de botnet ou de comando & controle, mas a presença de SSH aberto e de um servidor web desatualizado aumenta o risco de **brute‑force, exploração de CVEs e comprometimento**.  

---

## 2. Análise de Comportamento
| Fonte | Indício de atividade maliciosa |
|-------|--------------------------------|
| **Shodan – Tags** | Apenas a tag genérica **“cloud”**; nenhuma tag de botnet, scanner ou C2. |
| **Porta 22 (SSH)** | Serviço ativo com banner padrão; pode ser alvo de força‑bruta ou uso de credenciais fracas. |
| **Porta 80/443 (Apache 2.4.58)** | Versão vulnerável a dezenas de CVEs (incluindo alguns críticos de 2024‑2025). Não há relatórios de exploits conhecidos apontando especificamente este IP, mas a superfície de ataque está exposta. |
| **Hostname / Conteúdo** | `convitecenturion.com` – blog de cafés, aparentemente legítimo, sem indicadores de phishing ou malware nos conteúdos carregados. |
| **URLScan.io** | Nenhum escaneamento registrado, sugerindo baixa visibilidade pública ou ausência de análise automática recente. |

**Conclusão:** Não há evidência direta de que o IP esteja operando como infraestrutura de botnet ou C2. Contudo, a combinação de **SSH aberto** e **Apache vulnerável** oferece vetor atraente para adversários que buscam comprometer servidores web de pequeno/ médio porte.

---

## 3. Superfície de Ataque

### 3.1 Portas e Serviços
| Porta | Serviço | Versão / Banner |
|-------|----------|-----------------|
| **22** | OpenSSH | `OpenSSH_9.6p1 Ubuntu-3ubuntu13.13` |
| **80** | Apache httpd | `2.4.58 (Ubuntu)` – conteúdo do blog “Giovani e Adenir Oliveira…”. |
| **443** | Apache httpd (TLS) | `2.4.58 (Ubuntu)` – certificado Let's Encrypt (valido até 08/01/2026, CN = `convitecenturion.com`). |

### 3.2 Vulnerabilidades (CVEs) Identificadas
> **Nota:** O Shodan lista vulnerabilidades baseadas na versão dos softwares; a presença real depende da configuração específica.  

| Severidade | CVE | Resumo |
|------------|-----|--------|
| **Crítica** | CVE‑2024‑38476 | Information disclosure / SSRF / local script execution em Apache 2.4.59‑2.4.63. |
|  | CVE‑2024‑38474 | Substitution encoding issue no `mod_rewrite` que permite execução de scripts ou divulgação de código. |
|  | CVE‑2024‑38473 | Encoding problem no `mod_proxy` que pode contornar autenticação. |
|  | CVE‑2024‑38472 | SSRF em Windows (não aplicável aqui, mas indica risco de configuração similar). |
| **Alta** | CVE‑2025‑53020 | “Late Release of Memory after Effective Lifetime” – risco de memória corrompida. |
|  | CVE‑2025‑49812 | HTTP desynchronisation via TLS upgrade (mod_ssl). |
|  | CVE‑2025‑49630 | DoS em `mod_proxy_http2` com configuração de proxy reverso. |
|  | CVE‑2025‑23048 | Bypass de controle de acesso via TLS 1.3 session resumption. |
|  | CVE‑2024‑47252 | Insufficient escaping de dados de usuário em logs (potencial injection). |
|  | CVE‑2024‑43394 | SSRF que pode vazar hashes NTLM (em Windows). |
|  | CVE‑2024‑43204 | SSRF via `mod_proxy` + `mod_headers`. |
|  | CVE‑2024‑42516 | HTTP response splitting. |
|  | CVE‑2024‑40898 | SSRF em Windows com `mod_rewrite`. |
|  | CVE‑2024‑39573 | SSRF potencial via `mod_rewrite`. |
|  | CVE‑2024‑38477 | Null‑pointer do `mod_proxy` (DoS). |
|  | CVE‑2024‑38475 | Improper escaping no `mod_rewrite` (code exec / source disclosure). |
|  | CVE‑2024‑38471 | Encoding problem em `mod_proxy`. |
| **Média / Baixa** | Diversas (ex.: CVE‑2023‑38709, CVE‑2013‑4365, etc.) – vulnerabilidades históricas que podem ainda ser relevantes se o servidor não foi hardenado. |

> **Total de CVEs apontados:** 4 críticas, 17 altas, 9 médias, 2 baixas.  

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|------|
| **ASN** | **AS14061** – *DigitalOcean, LLC* |
| **ISP / Provedor** | **DigitalOcean, LLC** |
| **Organização** | DigitalOcean, LLC |
| **Localização** | **North Bergen, New Jersey, United States** (lat 40.8043, lon ‑74.0121) |
| **Cidade / Região** | North Bergen / New Jersey |
| **País** | United States |
| **Hostname principal** | `convitecenturion.com` |
| **Domínio** | `convitecenturion.com` |
| **Última Detecção (Shodan)** | 2025‑10‑27 |
| **UTC Offset** | America/New_York (UTC‑05/‑04) |

---

## 5. Recomendações de Investigação

1. **Correlacionar logs de firewall / IDS**  
   - Verificar tentativas de conexão nas portas 22, 80 e 443 nos últimos 30 dias.  
   - Identificar padrões de brute‑force SSH ou scans de vulnerabilidade web.

2. **Checar reputação em feeds de ameaças**  
   - Consultar fontes como AbuseIPDB, Spamhaus, AlienVault OTX, GreyNoise e VirusTotal para confirmar se o IP já foi reportado por atividades maliciosas.

3. **Analisar tráfego TLS**  
   - Verificar se o certificado Let’s Encrypt está correto e se há renegociações anômalas.  
   - Inspecionar SNI e cabeçalhos HTTP para detectar possíveis tentativas de bypass de virtual hosts.

4. **Teste de vulnerabilidades específicas**  
   - Realizar varredura controlada (ex.: Nessus, OpenVAS) focada nos CVEs críticos listados, principalmente aqueles que não dependem de ambiente Windows.  
   - Avaliar a presença de módulos Apache (mod_proxy, mod_rewrite, mod_ssl) que são vetores citados.

5. **Auditar acesso SSH**  
   - Verificar chaves autorizadas (`~/.ssh/authorized_keys`).  
   - Confirmar se a autenticação por senha está desabilitada ou reforçada (2FA, fail2ban).

6. **Verificar integridade do site**  
   - Baixar o conteúdo HTML/JS do `convitecenturion.com` e analisar por código malicioso ou redirecionamentos suspeitos.  
   - Verificar se há inclusão de recursos externos não confiáveis.

7. **Comunicar ao provedor (DigitalOcean Abuse)**  
   - Caso se confirme atividade suspeita ou comprometimento, abrir ticket de abuso em `abuse@digitalocean.com` com evidências coletadas.

8. **Monitoramento contínuo**  
   - Configurar alertas de Shodan/Passive DNS para mudanças de banner ou abertura de novas portas.  
   - Incluir o IP em “watchlist” de ferramentas de threat intel internas.

---

**Atenção:** As recomendações acima focam na **investigação e coleta de evidências**. Não são instruções de mitigação de vulnerabilidades específicas, mantendo o escopo do relatório centrado na avaliação de risco e nos próximos passos de análise.