---
layout: blog
title: "Confidential Kubernetes: Use Confidential Virtual Machines and Enclaves to improve your cluster security."
date: 2023-01-17
slug: "confidential-kubernetes"
---

**Authors:** Fabian Kammel (Edgeless Systems), (more to add...)

In this blog post, we will introduce the concept of Confidential Computing (CC) to improve the security and privacy properties of any computing environment. Further, we will show how the Cloud-Native ecosystem, and Kubernetes in particular, can benefit from the new compute paradigm.

## Intro

The [Whitepaper](https://confidentialcomputing.io/wp-content/uploads/sites/85/2022/11/CCC-A-Technical-Analysis-of-Confidential-Computing-v1.2_updated_2022-11-02.pdf) produced by the [Confidential Computing Consortium](https://confidentialcomputing.io/), a [LinuxFoundation](https://confidentialcomputing.io/wp-content/uploads/sites/85/2019/12/CCC_Overview.pdf) project, provides a great motivation for the usage of Confidential Computing:

   > "Data exists in three states: in transit, at rest, and in use. [...] Protecting sensitive data in all of its states is more critical than ever. Cryptography is now commonly deployed to provide both data confidentiality (stopping unauthorized viewing) and data integrity (preventing or detecting unauthorized changes). While techniques to protect data in transit and at rest are now commonly deployed, the third state - protecting data in use - is the new frontier."

Confidential computing aims to primarily solve the problem of **protecting data in use** by introducing a Trusted Execution Environment (TEE).

### Trusted Execution Environments

For more than a decade, Trusted Execution Environments (TEEs) have been available in commercial computing hardware, in the form of [Hardware Security Modules (HSMs)](https://en.wikipedia.org/wiki/Hardware_security_module) and [Trusted Platform Modules (TPMs)](https://www.iso.org/standard/50970.html). These technologies provide trusted environments for shielded computations. They are used to store highly sensitive cryptographic keys and carry out operations such as signing and encrypting data.

TPMs are optimized for low cost, allowing them to be integrated into mainboards and act as a system's physical root of trust. To keep the cost low, TPMs are limited in scope, i.e., they provide storage for only a few keys and are capable of just a small subset of cryptographic operations.

In contrast, HSMs are optimized for high performance, so they provide secure storage for far more keys and offer advanced physical attack detection mechanisms. Additionally, high-end HSMs can be programmed such that arbitrary code can be compiled and executed on them. The downside is that they are very costly. A managed CloudHSM from AWS costs [around $1.50 / hour](https://aws.amazon.com/cloudhsm/pricing/) or ~$13,500 / year.

In recent years a new kind of TEE has gained popularity. Technologies like [AMD SEV](https://developer.amd.com/sev/), [Intel SGX](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html), and [Intel TDX](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html) provide TEEs that are closely integrated with userspace. Rather than low-power or high-performance devices that support specific use cases, these TEEs shield normal processes or virtual machines and can do so with relatively low overhead. These technologies each have different design goals, advantages, and limitations, and they are available in different environments including consumer laptops, servers, and mobile devices.

Additionally, we should mention [ARM TrustZone](https://www.arm.com/technologies/trustzone-for-cortex-a) which is optimized for embedded devices such as smartphones, tablets, and smart TVs, as well as [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) which are only available on [Amazon Web Services](https://aws.amazon.com/) and have a different attacker model compared to the CPU-based solutions by Intel and AMD.

### Security Properties and Feature Set

In the following, we will review the security properties and additional features these new technologies bring to the table. Not all solutions will provide all properties, and we will discuss each technology in further detail in their respective chapter.

The **Confidentiality** property ensures that information cannot be viewed while it is in use in the TEE. This provides us with the highly desired feature to secure **data in use**. Depending on the specific TEE used, both code and data may be protected from outside viewers.

Confidentiality is a great feature, but an attacker would still be able to manipulate or inject arbitrary code and data for the TEE to execute and therefore easily leak critical information. **Integrity** allows a TEE owner to check that neither code nor data has been tempered before running critical computations.

*Availability* is the third basic property often [discussed in information security](https://en.wikipedia.org/wiki/Information_security). This property is outside the scope of most TEEs. Usually, they can be controlled (shutdown, restarted, ...) by some higher-level concept. This could be the CPU itself, a hypervisor, or a kernel. This is to preserve the availability of the overall system, and not the TEE itself. When running in the cloud the availability is usually guaranteed by the cloud provider in [terms of Service Level Agreements (SLAs)](https://cloud.google.com/compute/sla) and is not cryptographically enforceable.

Confidentiality and Integrity by themselves would only be helpful in some cases. For example, consider a TEE running in a remote cloud. How would you know that the TEE is genuine and running your intended software? It could be an imposter stealing your data as soon as you send it over. This fundamental problem is addressed by **Attestability**. Remote attestation allows us to verify the identity, confidentiality, and integrity of TEEs based on cryptographic certificates issued from the hardware itself.

TEEs can hold and process information that needs to persist even beyond their lifespan. That could mean across restarts, different versions, or platform migrations. Therefore **Recoverability** is an important feature. Data and the state of a TEE need to be sealed before they are written to persistent storage to maintain confidentiality and integrity guarantees. The access to such sealed data needs to be well-defined. In most cases, the unsealing is bound to a TEE's identity. Hence, making sure the recovery can only happen in the same confidential context.

This does not have to limit the flexibility of the overall system. The [migration agent (MA) of AMD SEV-SNP](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf) allows users to migrate a confidential virtual machine to a different host system. All the while keeping the security properties of the TEE intact.

## Feature Comparison

In the following, we will dive a little bit deeper into the specific implementations, compare supported features and analyze the security properties.

### AMD SEV

AMD's [Secure Encrypted Virtualization (SEV)](https://developer.amd.com/sev/) technologies are a set of features to enhance the security of virtual machines on AMD's server CPUs. SEV transparently encrypts the memory of each VM with a unique key.
SEV can also calculate a signature of the memory contents, which can be sent to the VM's owner as an attestation that the memory was encrypted correctly by the firmware.
The second generation of SEV called [Encrypted State (SEV-ES)](https://www.amd.com/system/files/TechDocs/Protecting%20VM%20Register%20State%20with%20SEV-ES.pdf) provides additional protection from the hypervisor by encrypting all CPU register contents when a VM stops running.
The third generation of SEV called [Secure Nested Paging (SNP)](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf) is designed to prevent software-based integrity attacks and reduce the risk associated with
compromised memory integrity. The basic principle of SEV-SNP integrity is that if a VM can read
a private (encrypted) memory page, it must always read the value it last wrote.
Additionally, by allowing the guest to obtain remote attestation statements dynamically, SNP enhances the remote attestation capabilities of SEV.

SEV is continually upgraded with new features and improvements with each new generation. The Linux community makes these features available as part of the KVM hypervisor, host, and guest kernel. The first SEV features were discussed and implemented in [2016](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/kaplan). After that, the SEV-ES feature set was implemented in [2020](https://www.phoronix.com/news/AMD-SEV-ES-Linux-2020-Patches). Recently, the latest feature set was [merged in Linux 5.19 in July 2022](https://www.phoronix.com/news/AMD-SEV-SNP-Arrives-Linux-5.19) and enabled support for SEV-SNP.

Confidential VMs based on AMD SEV-SNP are [available in Microsoft Azure since July 2022](https://azure.microsoft.com/en-us/updates/azureconfidentialvm/). Similarly, [Google Cloud Platform (GCP)](https://cloud.google.com/compute/confidential-vm/docs/about-cvm) offers confidential VMs based on AMD SEV-ES.

### Intel SGX

[Intel's Software Guard Extensions](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html) is available since 2015 [introduced with the Skylake architecture](https://ark.intel.com/content/www/us/en/ark/products/88172/intel-xeon-processor-e31220-v5-8m-cache-3-00-ghz.html).

SGX is a new instruction set that enables users to create a protected and isolated process called an *enclave*.
It provides a reverse sandbox that protects enclaves from the OS, BIOS, firmware, and any other privileged execution context.

The enclave memory cannot be read or written from outside the enclave, regardless of the current privilege level and CPU mode. The only way to call an enclave function is through a new instruction that performs several protection checks. Its memory is encrypted. Tapping the memory or connecting the DRAM modules to another system will yield only encrypted data. The memory encryption key randomly changes every power cycle. The key is stored within the CPU and is not accessible.

The 3rd Generation Xeon CPUs (aka Ice Lake Server - "ICX") did switch to using a technology called [Total Memory Encryption - Multi-Key (TME-MK)](https://www.intel.com/content/www/us/en/developer/articles/news/runtime-encryption-of-memory-with-intel-tme-mk.html) that uses AES-XTS, moving away from the [Memory Encryption Engine](https://eprint.iacr.org/2016/204.pdf) that the consumer and Xeon E CPUs used. This increased the possible [EPC](https://sgx101.gitbook.io/sgx101/sgx-bootstrap/enclave#enclave-page-cache-epc) size (up to 512GB/CPU) as well as gained a big increase in performance. More info about SGX on multi-socket platforms can be found in the [Whitepaper](https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/supporting-intel-sgx-on-mulit-socket-platforms.pdf)

A complete list of supported platforms is available on [ark.intel.com](https://ark.intel.com/content/www/us/en/ark/search/featurefilter.html?productType=873&2_SoftwareGuardExtensions=Yes%20with%20both%20Intel%C2%AE%20SPS%20and%20Intel%C2%AE%20ME).

However, there are still several security limitations faced by SGX. Such as Cache timing attacks, physical attacks, untrusted I/O, or malicious microcode patching.

[Several SGX-specific attacks](https://arxiv.org/pdf/2006.13598.pdf) were published. Among others [Prime+Probe](https://gruss.cc/files/malware_guard_extension.pdf) and [SGAxe](https://sgaxe.com/files/SGAxe.pdf).

> TODO: Should we mention attacks? If we do, we should also mention attacks on all technologies. Do we have a stance / recommendation here or do we provide the information and let the reader decide?

SGX is available on [Azure](https://azure.microsoft.com/de-de/updates/intel-sgx-based-confidential-computing-vms-now-available-on-azure-dedicated-hosts/), [Alibaba Cloud](https://azure.microsoft.com/de-de/updates/intel-sgx-based-confidential-computing-vms-now-available-on-azure-dedicated-hosts/), [IBM](https://cloud.ibm.com/docs/bare-metal?topic=bare-metal-bm-server-provision-sgx), and many more.

### Intel TDX

Where Intel SGX aims to protect the context of a single process, [Intel's Trusted Domain Extensions](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html) protects a full virtual machine and is therefore most closely comparable to AMD SEV.

As with SEV-SNP support for TDX was [merged in Linux Kernel 5.19](https://www.phoronix.com/news/Intel-TDX-For-Linux-5.19), but hardware support will land with [Saphire Rapids](https://en.wikipedia.org/wiki/Sapphire_Rapids) in early 2023.

## Overhead Analysis

The benefits that confidential computing technologies provide via strong isolation and enhanced security to customer data and workloads are not for free. Quantifying this impact isn't easy and depends on many factors: The TEE technology, the benchmark, the metrics, and the type of workload have a huge impact on the induced performance overhead.

Intel SGX-based TEEs are hard to benchmark as [shown](https://arxiv.org/pdf/2205.06415.pdf) [by](https://www.ibr.cs.tu-bs.de/users/mahhouk/papers/eurosec2021.pdf) [different papers](https://dl.acm.org/doi/fullHtml/10.1145/3533737.3535098). Since enclaves are process isolated, the operating system's libraries are not available and additional SDKs are required to compile programs for SGX. The chosen SDK as well as the resource requirements (especially large memory requirements) have a huge impact on performance. If an application is well suited to run inside an enclave a single-digit percentage overhead can be expected.

Confidential virtual machines based on AMD SEV-SNP require no changes to the executed program and operating system and are a lot easier to benchmark. A [benchmark from Azure and AMD shows](https://community.amd.com/t5/business/microsoft-azure-confidential-computing-powered-by-3rd-gen-epyc/ba-p/497796) that SEV-SNP VM overhead is <10%, sometimes as low as 2%.

Although there is a performance overhead, it should be low enough to enable real-world workloads to run in these protected environments and improve the security and privacy of our data.

## Confidential Computing compared to FHE, ZKP, and MPC

Fully Homomorphic Encryption (FHE), Zero Knowledge Proof/Protocol (ZKP), and Multi-Party Computations (MPC) are all a form of encryption or cryptographic protocols that offer similar security guarantees to confidential computing but do not require hardware support.

Fully (also partially and somewhat) homomorphic encryption allows one to perform computations, such as addition or multiplication, on encrypted data. This provides the property of encryption in use but does not provide integrity protection or attestation.

Zero Knowledge Proofs or Protocols are a privacy-preserving technique (PPT) that allows one party to prove facts about their data without revealing anything else about the data. ZKP can be used instead of or in addition to confidential computing to protect the privacy of the involved parties and their data. Similarly, Multi-Party Computation enables multiple parties to work together on a computation, i.e, each party provides their data to the result, without leaking their data to any of the other parties.

## Use Cases of Confidential Computing

The presented confidential computing platforms show that both the isolation of a single process and therefore minimization of the trusted computing base, and the isolation of a full virtual machine are possible. This already enabled a lot of interesting and secure projects to emerge:

### Confidential Containers

The [Confidential Containers project](https://github.com/confidential-containers) enables users to run a container inside a confidential context. It provides an abstraction layer so that users do not need to interface directly with the confidential computing hardware.

Confidential Containers is a [CNCF sandbox project](https://www.redhat.com/en/blog/what-confidential-containers-project).

> TODO: @Tobin/Mikko (or other CoCo folks) can you expand on this chapter?

### Managed Confidential Kubernetes

[Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-node-pool-aks) and [GCP](https://cloud.google.com/blog/products/identity-security/announcing-general-availability-of-confidential-gke-nodes) both support the use of confidential virtual machines as worker nodes for their managed Kubernetes offerings.

Both services aim for better workload protection and security guarantees by enabling memory encryption for container workloads. However, they don't seek to fully isolate the cluster or workloads against the service provider or infrastructure. Specifically, they don't offer a dedicated confidential control plane or expose attestation capabilities for the confidential cluster/nodes.

Azure also enables [Confidential Containers](https://github.com/confidential-containers) in their managed Kubernetes offering. They support the creation based on [Intel SGX enclaves](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers-enclaves) and [AMD SEV-based VMs](https://techcommunity.microsoft.com/t5/azure-confidential-computing/microsoft-introduces-preview-of-confidential-containers-on-azure/ba-p/3410394).

### Constellation

[Constellation is a Kubernetes engine](https://github.com/edgelesssys/constellation) that aims to provide the best possible data security. It wraps your entire Kubernetes cluster into a single confidential context that is shielded from the underlying cloud infrastructure. Everything inside is always encrypted, including at runtime in memory. It shields both the worker and control plane nodes. In addition, it already integrates with popular CNCF software such as Cilium for secure networking and provides extended CSI drivers to write data securely.

> TODO: Please add any interesting open-source projects in the space we should highlight!

## Where are we today? Vendors, Limitations, and FOSS landscape

As we have seen in the previous sections confidential computing is a powerful new concept to improve security, but we are still in the (early) adoption phase. New products are starting to emerge to take advantage of the new properties.

Google and Microsoft are the first major cloud providers to have confidential offerings. Still, these offerings are limited to compute and end-to-end solutions for confidential databases, cluster networking, and load balancers have to be self-managed.

At the same time using these new technologies provides us with new opportunities to bring even the most sensitive workloads into the cloud. This enables them to leverage all the tools in the CNCF landscape.

## Call to action

If you are currently working on a high-security product that struggles to run in the public cloud due to legal requirements or are looking to bring the privacy and security of your cloud-native project to the next level: Reach out to all the great projects we have highlighted! Everyone is keen to improve security of our ecosystem and you can play a vital role in that journey.

* [Confidential Containers](https://github.com/confidential-containers)
* [Constellation: Always encrypted K8s](https://github.com/edgelesssys/constellation)

> TODO: Do we have a full list of CNCF-related CC projects? We should link to their GitHub to encourage adoption and contributions.
