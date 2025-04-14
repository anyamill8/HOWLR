# HOWLR

This work presents HOWLR, a novel, witness-based system for detecting BGP hijacks that leverages verifiable, certificate-hosting neighbors within the same /24 prefix as a potential victim. Unlike traditional detection approaches that require widespread deployment, infrastructure access, or preexisting routing knowledge, HOWLR is designed for lightweight, node-level deployment—providing strong protection through strategic use of PKI and the structural properties of BGP routing. Evaluations across real-world applications, autonomous systems, and geographic regions demonstrate that a meaningful portion of the Internet can be protected with minimal scanning and runtime overhead. In particular, HOWLR proved effective in security-sensitive ecosystems like Bitcoin and Tor, with integration into Bitcoin testnet confirming its practical deployability.

While HOWLR is not universally applicable—prefixes lacking sufficient witnesses or hosting only self-signed certificates remain unprotected—it represents a promising shift toward deployable, decentralized routing security. By identifying a path for individual users to protect themselves without coordination from ISPs or global infrastructure, HOWLR offers a critical tool in addressing the ongoing threat of BGP hijacking in modern networks.

# Contents

This repository holds witnessSearch.py--a piece of code critical for proving the viability of witness-based detection. It also contains all four optimizaton schemes for witnessSearch.py, demarcated with "O#."

This repository also holds the code for HOWLR Light and HOWLR Strong, seperated into two distinct files for ease of use. This code builds upon witnessSearch.py to find a reasonable number of witnesses to protect a particular IP. 

Finally, this repository holds BitcoinApplicaton.py and applicationOutput.txt, which demonstrate how HOWLR can be integrated to work with a security-sensitive network like Bitcoin. The output of a 0.5 hour test on the Bitcoin Testnet has been collected in applicationOutput.txt.
