
The output reports from assign_cwe are stored here per CVE.

There is a folder per CVE. 

Taking CVE-2022-41193 as an arbitrary example, the main files are:
1. Analyzer agent
   1. [CVE-2022-41193/CVE-2022-41193_analyzer_input.md](./reports/CVE-2022-41193/CVE-2022-41193_analyzer_input.md)
      1. This contains the vulnerability input data and retriever results
   2. [CVE-2022-41193/CVE-2022-41193_analysis.md](./reports/CVE-2022-41193/CVE-2022-41193_analysis.md)
2. Critic agent
   1. [CVE-2022-41193/CVE-2022-41193_critic_input.md](./reports/CVE-2022-41193/CVE-2022-41193_critic_input.md)
   2. [CVE-2022-41193/CVE-2022-41193_criticism.md](./reports/CVE-2022-41193/CVE-2022-41193_criticism.md)
3. Resolver agent
   1. [CVE-2022-41193/CVE-2022-41193_resolver_input.md](./reports/CVE-2022-41193/CVE-2022-41193_resolver_input.md)
   2. [CVE-2022-41193/CVE-2022-41193_**resolution.md**](./reports/CVE-2022-41193/CVE-2022-41193_resolver_input.md)
      1. **this contains the final assignment**