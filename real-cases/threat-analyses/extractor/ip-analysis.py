from ollama import Client
import requests
import sys
import json

client=Client()

ip = '161.35.50.50'

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
    'Referer': 'https://urlscan.io/',
    'DNT': '1',
}

print(f"Coletando informações para o IP: {ip}...")

sanitized_ip = ip.replace('.', '_')
report_filename = f"threat_report_{sanitized_ip}.md"

try:
    # 1. Usar a API do Shodan para dados estruturados
    shodan_host_info = requests.get(f'https://www.shodan.io/host/{ip}', headers=headers)
    shodan_host_info.raise_for_status()  # Verifica se a requisição foi bem-sucedida
    shodan_text = shodan_host_info.text.replace('"""', '\\"\\"\\"') # Escapa aspas triplas

    # 2. Coletar dados de outras fontes
    ipinfo_response = requests.get(f'https://ipinfo.io/{ip}/json', headers=headers)
    ipinfo_response.raise_for_status()  # Verifica se a requisição foi bem-sucedida

    arin_whois_response = requests.get(f'https://whois.arin.net/rest/ip/{ip}', headers=headers)
    arin_whois_response.raise_for_status()

    arin_rdap_response = requests.get(f'https://rdap.arin.net/registry/ip/{ip}', headers=headers)
    arin_rdap_response.raise_for_status()

    url_scan_reponse = requests.get(f'https://urlscan.io/api/v1/search/?q=ip:{ip}', headers=headers)
    url_scan_reponse.raise_for_status()

    # Combinar todos os dados em uma única string para a IA
    combined_content = f"""
    ## DADOS COLETADOS PARA ANÁLISE DE THREAT INTELLIGENCE

    ### 1. Informações do Shodan
    ```html
    {shodan_text}
    ```

    ### 2. Informações do IPInfo.io
    ```json
    {ipinfo_response.text}
    ```

    ### 3. Informações do ARIN (WHOIS)
    ```
    {arin_whois_response.text}
    ```

    ### 4. Informações do ARIN (RDAP)
    ```json
    {arin_rdap_response.text}
    ```

    ### 5. Resultados do URLScan.io
    ```json
    {url_scan_reponse.text}
    ```

    """
    
except requests.exceptions.HTTPError as e:
    print(f"Erro ao fazer requisição HTTP para uma das fontes de dados: {e}")
    print(f"URL que falhou: {e.request.url}")
    sys.exit(1)

prompt = """
Você é um especialista em Threat Intelligence. Analise os dados brutos fornecidos (em formato JSON e texto) sobre um endereço IP e gere um relatório de inteligência de ameaças.

**Seu relatório deve conter:**
1.  **Resumo Executivo:** Um parágrafo conciso com as principais descobertas (localização, ISP, comportamento suspeito, portas críticas).
2.  **Análise de Comportamento:** Avalie se há indícios de atividade maliciosa, como associação com botnets, scanners, ou servidores de C2, com base nos dados do Shodan e outras fontes.
3.  **Superfície de Ataque:**
    - Liste todas as **portas abertas** e os **serviços** correspondentes.
    - Liste **vulnerabilidades (CVEs)** identificadas pelo Shodan, se houver, de forma breve, apontando sua relação com possíveis comportamentos maliciosos.
4.  **Informações de Rede e Geográficas:**
    - **ASN:** Número e nome da organização.
    - **Provedor (ISP):** Nome do provedor.
    - **Localização:** Cidade, Região, País.
5.  **Recomendações:** Sugira os próximos passos para uma investigação mais aprofundada (ex: verificar logs de firewall, procurar o IP em feeds de ameaças, etc.).
6. Seu foco é identificar potenciais riscos e comportamentos maliciosos associados ao IP analisado.

**Não fornecer orientação de mitigações de vulnerabilidades apontadas pelo Shodan. Seu papel é identificar comportamentos e riscos associados ao IP analisado para proteção de outros usuários, não fornecer orientação de proteção para o sistema dele.**
**Formato:** Use Markdown e responda em **português do Brasil**.

**Sempre Iniciar o relatório com o seguinte formato de cabeçalho**
# Relatório de Threat Intelligence – IP **(Número do IP Analisado)**

> **Fonte dos dados**: (Fontes utilizadas, ex: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io).  
> **Última coleta Shodan**: (Data de Última Coleta).  
""".strip()

message = [
    {
        'role': 'system',
        'content': 'Você é um especialista em Threat Intelligence, com foco em análise de vetores maliciosos, identificando IPs, hosts e comportamentos maliciosos.'
    },
    {
        'role': 'user',
        'content': prompt
    },
    {
      'role': 'user',
      'content': combined_content
    }
]

print(f"Analisando e gerando relatório...")
full_response = []
try:
    for part in client.chat('gpt-oss:120b-cloud', messages=message, stream=True):
      print(part['message']['content'], end='', flush=True)
      content = part['message']['content']
      full_response.append(content)
except Exception as e:
    print(f"\n\nErro ao comunicar com o modelo de IA: {e}")
    sys.exit(1)

print(f"\n\n--- Fim da Análise ---")

with open(report_filename, "w", encoding="utf-8") as f:
    f.write("".join(full_response))

print(f"[+] Relatório salvo com sucesso em: {report_filename}")