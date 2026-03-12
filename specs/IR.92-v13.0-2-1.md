![image](https://cdn-mineru.openxlab.org.cn/result/2026-03-11/b8096535-fdef-4a45-98dd-e545fe59988d/124b723a1e3a8ae069f1e9dfcb6740072d1a17f3d9138d1cef33b08f64612757.jpg)


# IMS Profile for Voice and SMS

Version 13.0 

23 April 2019 

This is a Non-binding Permanent Reference Document of the GSMA 

# Security Classification: Non-confidential

Access to and distribution of this document is restricted to the persons permitted by the security classification. This document is confidential to the Association and is subject to copyright protection. This document is to be used only for the purposes for which it has been supplied and information contained in it must not be disclosed or in any other way made available, in whole or in part, to persons other than those permitted under the security classification without the prior written approval of the Association. 

# Copyright Notice

Copyright $\circledcirc$ 2019 GSM Association 

# Disclaimer

The GSM Association (“Association”) makes no representation, warranty or undertaking (express or implied) with respect to and does not accept any responsibility for, and hereby disclaims liability for the accuracy or completeness or timeliness of the information contained in this document. The information contained in this document may be subject to change without prior notice. 

# Antitrust Notice

The information contain herein is in full compliance with the GSM Association’s antitrust compliance policy. 

# Table of Contents

# 1 Introduction 5

1.1 Overview 5 

1.2 Relationship to existing standards 6 

1.2.1 3GPP specifications 6 

1.3 Scope 6 

1.4 Definition of Acronyms and Terms 6 

1.4.1 Acronyms 6 

1.4.2 Terms 9 

1.5 Document Cross-References 10 

# 2 IMS Feature Set 14

2.1 General 14 

2.2 Support of generic IMS functions 14 

2.2.1 SIP Registration Procedures 14 

2.2.2 Authentication 16 

2.2.3 Addressing 17 

2.2.4 Call Establishment and Termination 19 

2.2.5 Forking 20 

2.2.6 The use of Signalling Compression 21 

2.2.7 Early media and announcements 21 

2.2.8 SIP Session Timer 22 

2.2.9 SIP OPTIONS 22 

2.3 Supplementary Services 22 

2.3.1 Supplementary Services Overview 22 

2.3.2 Supplementary Service Configuration 23 

2.3.3 Ad-Hoc Multi Party Conference 25 

2.3.4 Communication Waiting 26 

2.3.5 Message Waiting Indication 27 

2.3.6 Originating Identification Restriction 27 

2.3.7 Terminating Identification Restriction 27 

2.3.8 Communication Diversion 27 

2.3.9 Communication Barring 28 

2.3.10 Communication Hold 29 

2.3.11 Explicit Communication Transfer - Consultative 29 

2.3.12 Originating Identification Presentation 29 

2.4 Call Set-up Considerations 30 

2.4.1 SIP Precondition Considerations 30 

2.4.2 Integration of resource management and SIP 30 

2.4.3 Voice Media Considerations 32 

2.4.4 Multimedia Considerations 34 

2.4.5 Call Composer Service 35 

2.5 SMS over IP 35 

2.6 User Agent and Server Headers 36 

# 3 IMS Media 38

3.1 General 38 

3.2 Voice Media 38 

3.2.1 Codecs 38 

3.2.2 RTP Profile and SDP Considerations 39 

3.2.3 Data Transport 40 

3.2.4 RTCP Usage 40 

3.2.5 Speech Payload Format Considerations 42 

3.2.6 Jitter Buffer Management Considerations 43 

3.2.7 Front End Handling 43 

3.3 DTMF Events 43 

# 4 Radio and Packet Core Feature Set 43

4.0 General 43 

4.1 Robust Header Compression 43 

4.2 LTE Radio Capabilities 44 

4.2.1 Radio Bearers 44 

4.2.2 DRX Mode of Operation 44 

4.2.3 RLC configurations 44 

4.2.4 GBR and NGBR Services, GBR Monitoring Function 44 

4.2.5 E-UTRA NR Dual connectivity 45 

4.3 Bearer Management 45 

4.3.1 EPS Bearer Considerations for SIP Signalling, HTTP for XCAP and HTTP Content Server 45 

4.3.2 EPS Bearer Considerations for Voice 46 

4.3.3 EPS Bearer Considerations for voice media on emergency PDN Connection 47 

4.4 P-CSCF Discovery 47 

# 5 Common Functionalities 48

5.1 IP Version 48 

5.2 Emergency Service 48 

5.2.1 General 48 

5.2.2 Interactions between supplementary services and PSAP callback 49 

5.2.3 UE location management 50 

5.3 Roaming Considerations 50 

5.4 Accesses in addition to E-UTRAN 50 

5.5 Data Off and Services Availability 50 

5.5.1 General 50 

5.5.2 Supplementary Service Settings Management 51 

5.5.3 Voice Calls and SMS over IMS 51 

5.6 Voice Calls and Smart Congestion Mitigation 51 

5.7 Capability Discovery 51 

5.8 HTTP Content Server 51 

# Annex A Complementing IMS with CS 53

A.1 General 53 

A.2 Domain Selection 53 

A.3 SR-VCC 53 

A.4 IMS Voice service settings management when using CS access 54 

A.5 Emergency Service 54 

A.6 Roaming Considerations 55 

A.7 SMS Support 55 

A.8 Call Waiting in the CS domain 56 

A.9 USSD 56 

# Annex B Features needed in certain regions 57

B.1 General 57 

B.2 Global Text Telephony over IP 57 

B.3 Service Specific Access Control 58 

# Annex C MNO provisioning and Late Customization 59

C.1 General 59 

C.2 Configuration Methods 59 

C.2.1 Remote Client Configuration for MNO provisioning 59 

C.2.2 Late Customization 59 

C.1 Configuration Parameters 59 

# 6 Annex D USSI 64

D.1 Introduction 64 

D.1.1 Overview 64 

D.2 IMS Feature Set 64 

D.2.1 General 64 

D.2.2 Support of generic IMS functions 64 

D.2.3 USSI Considerations 64 

D.3 SDP negotiation 65 

D.4 Common Functionalities 65 

D.4.1 Data Off 65 

D.5 Complementing IMS with CS 65 

D.5.1 General 65 

D.5.2 Domain Selection 65 

# Annex D Document Management 67

D.1 Document History 67 

D.2 Other Information 68 

# 1 Introduction

# 1.1 Overview

The IP Multimedia Subsystem (IMS) Profile for Voice and SMS, documented in this Permanent Reference Document (PRD), defines a profile that identifies a minimum mandatory set of features which are defined in 3GPP specifications that a wireless device (the User Equipment (UE)) and network are required to implement in order to guarantee an interoperable, high quality IMS-based telephony service and IMS-based and SGs-based Short Message Service (SMS) over Long Term Evolution (LTE) radio access. The content includes the following aspects: 

 IMS basic capabilities and supplementary services for telephony [Chapter 2]. 

 Real-time media negotiation, transport, and codecs [Chapter 3]. 

 LTE radio and evolved packet core capabilities [Chapter 4]. 

 Functionality that is relevant across the protocol stack and subsystems [Chapter 5]. 

Additional features that need to be implemented for the UEs and networks that wish to support concurrent Circuit Switched (CS) coverage [Annex A]. 

Additional features that only a subset of the IMS telephony operators needs to support in certain markets [Annex B]. 

UE configuration to provide all necessary information to connect to, and receive voice service and SMS from, a specific IMS telephony operator [Annex C]. 

Support for Unstructured Supplementary Service Data (USSD) Simulation Service in IMS (USSI) as optional feature [Annex D]. 

The UE and network protocol stacks forming the scope of the IMS Profile for Voice and SMS are depicted in figure 1.1 below: 

![image](https://cdn-mineru.openxlab.org.cn/result/2026-03-11/b8096535-fdef-4a45-98dd-e545fe59988d/e09f3c24e706716d65c9387f80e4f0eff860a8e0dbd0ad65c8f1958ab7066dc7.jpg)



Figure 1.1: Depiction of UE and Network Protocol Stacks in IMS Profile for Voice


The main body of this PRD is applicable for a scenario where IMS telephony is deployed over LTE in a standalone fashion without relying on any legacy infrastructure, packet or circuit switched. In order to be compliant with IMS Profile for Voice and SMS, the UEs and networks must be compliant with all of the normative statements in the main body. 

Annex A defines the profile for an alternative approach where IMS telephony is deployed with a certain degree of reliance on an existing 3GPP circuit switched network infrastructure. 

Whenever there are additional requirements to the main profile, these are explicitly stated. In order to be compliant with the functionality described in Annex A, the UEs and networks must be compliant with all of the normative statements in Annex A as well as to all of the normative statements in the main body of the PRD that are unaltered by Annex A. 

# 1.2 Relationship to existing standards

# 1.2.1 3GPP specifications

This profile is solely based on the open and published 3GPP specifications as listed in the Section 1.5. 3GPP Release 8, the first release supporting LTE, is taken as a basis. It should be noted, however that not all the features mandatory in 3GPP Release 8 are required for compliance with this profile. 

Conversely, some features required for compliance with this profile are based on functionality defined in 3GPP Release 9 or higher releases. 

All such exceptions are explicitly mentioned in the following sections along with the relevant Release 8 or higher 3GPP release specifications, respectively. 

Unless otherwise stated, the latest version of the referenced specifications for the relevant 3GPP release applies. 

# 1.3 Scope

This document defines a profile for voice over IMS over LTE, and for SMS over IMS and SMS over SGs, by listing a number of Evolved Universal Terrestrial Radio Access Network (E-UTRAN), Evolved Packet Core, IMS core, and UE features that are considered essential to launch interoperable services. The defined profile is compliant with 3GPP specifications. The scope of this profile is the interface between UE and network. 

The profile does not limit anybody, by any means, to deploy other standardized features or optional features, in addition to the defined profile. 

# 1.4 Definition of Acronyms and Terms

# 1.4.1 Acronyms

<table><tr><td>Acronym</td><td>Description</td></tr><tr><td>3GPP</td><td>3rd Generation Partnership Project</td></tr><tr><td>AM</td><td>Acknowledged Mode</td></tr><tr><td>AMR</td><td>Adaptive Multi-Rate</td></tr><tr><td>AMR-WB</td><td>Adaptive Multi-Rate Wideband</td></tr><tr><td>APN</td><td>Access Point Name</td></tr><tr><td>AVP</td><td>Audio Video Profile</td></tr><tr><td>AVPF</td><td>AVP Feedback Profile</td></tr><tr><td>BSF</td><td>Bootstrapping Server Function</td></tr><tr><td>CB</td><td>Communication Barring</td></tr><tr><td>CDIV</td><td>Communication Diversion</td></tr><tr><td>CFNL</td><td>Communication Forwarding on Not Logged-in</td></tr><tr><td>CFNRc</td><td>Communication Forwarding on Not Reachable</td></tr><tr><td>CN</td><td>Core Network</td></tr><tr><td>CS</td><td>Circuit Switched</td></tr><tr><td>CSFB</td><td>CS Fallback</td></tr><tr><td>CW</td><td>Communication Waiting</td></tr><tr><td>DRB</td><td>Data Radio Bearer</td></tr><tr><td>DRX</td><td>Discontinuous Reception</td></tr><tr><td>DTX</td><td>Discontinuous Transmission</td></tr><tr><td>ECT</td><td>Explicit Communication Transfer</td></tr><tr><td>EPC</td><td>Evolved Packet Core</td></tr><tr><td>eNB</td><td>eNodeB</td></tr><tr><td>EN-DC</td><td>E-UTRA NR Dual Connectivity</td></tr><tr><td>EPS</td><td>Evolved Packet System</td></tr><tr><td>E-UTRAN</td><td>Evolved Universal Terrestrial Radio Access Network</td></tr><tr><td>EVS</td><td>Enhanced Voice Services</td></tr><tr><td>FDD</td><td>Frequency-Division Duplexing</td></tr><tr><td>GBR</td><td>Guaranteed Bit Rate</td></tr><tr><td>GRUU</td><td>Globally Rtable User agent URI</td></tr><tr><td>GSM</td><td>Global System for Mobile communications</td></tr><tr><td>GTT-IP</td><td>Global Text Telephony over IP</td></tr><tr><td>ICS</td><td>IMS Centralized Services</td></tr><tr><td>ICSI</td><td>IMS Communication Service Identifier</td></tr><tr><td>IM</td><td>IP Multimedia</td></tr><tr><td>IMPU</td><td>IP Multimedia Public Identity</td></tr><tr><td>IMS</td><td>IP Multimedia Subsystem</td></tr><tr><td>IMS-AKA</td><td>IMS Authentication and Key Agreement</td></tr><tr><td>IMSI</td><td>International Mobile Subscriber Identity</td></tr><tr><td>IP</td><td>Internet Protocol</td></tr><tr><td>IPv4</td><td>Internet Protocol Version 4</td></tr><tr><td>IPv6</td><td>Internet Protocol Version 6</td></tr><tr><td>ISIM</td><td>IM Services Identity Module</td></tr><tr><td>LTE</td><td>Long Term Evolution</td></tr><tr><td>MGW</td><td>Media Gateway</td></tr><tr><td>MMTel</td><td>Multimedia Telephony</td></tr><tr><td>MO</td><td>Managed Object</td></tr><tr><td>MRFP</td><td>Media Resource Function Processor</td></tr><tr><td>MS</td><td>Mobile Station</td></tr><tr><td>MS-ISDN</td><td>Mobile Subscriber ISDN Number</td></tr><tr><td>MWI</td><td>Message Waiting Indication</td></tr><tr><td>NGBR</td><td>Non Guaranteed Bit Rate</td></tr><tr><td>PCC</td><td>Policy and Charging Control</td></tr><tr><td>PCRF</td><td>Policy and Charging Rules Function</td></tr><tr><td>P-CSCF</td><td>Proxy - Call Session Control Function</td></tr><tr><td>PDN</td><td>Packet Data Network</td></tr><tr><td>PS</td><td>Packet Switched</td></tr><tr><td>QCI</td><td>Quality of Service Class Indicator</td></tr><tr><td>RAT</td><td>Radio Access Technology</td></tr><tr><td>RLC</td><td>Radio Link Control</td></tr><tr><td>RoHC</td><td>Robust Header Compression</td></tr><tr><td>RR</td><td>Receiver Report</td></tr><tr><td>RTCP</td><td>RTP Control Protocol</td></tr><tr><td>RTP</td><td>Real Time Protocol</td></tr><tr><td>SCC AS</td><td>Service Centralization and Continuity Application Server</td></tr><tr><td>SDES</td><td>Source Description</td></tr><tr><td>SDP</td><td>Session Description Protocol</td></tr><tr><td>SG</td><td>Signalling Gateway</td></tr><tr><td>SigComp</td><td>Signalling Compression</td></tr><tr><td>simservs</td><td>MMTel supplementary services XML document</td></tr><tr><td>SIP</td><td>Session Initiation Protocol</td></tr><tr><td>SMSoIP</td><td>SMS over IP</td></tr><tr><td>SR</td><td>Sender Report</td></tr><tr><td>SRB</td><td>Signalling Radio Bearer</td></tr><tr><td>SR-VCC</td><td>Single Radio Voice Call Continuity</td></tr><tr><td>TAS</td><td>Telephony Application Server</td></tr><tr><td>TDD</td><td>Time-Division Duplexing</td></tr><tr><td>TFO</td><td>Tandem-Free Operation</td></tr><tr><td>TrFO</td><td>Transcoder-Free Operation</td></tr><tr><td>TTY</td><td>Teletype Writer</td></tr><tr><td>UDP</td><td>User Datagram Protocol</td></tr><tr><td>UE</td><td>User Equipment</td></tr><tr><td>UICC</td><td>Universal Integrated Circuit Card</td></tr><tr><td>UM</td><td>Unacknowledged Mode</td></tr><tr><td>URI</td><td>Uniform Resource Identifier</td></tr><tr><td>USSD</td><td>Unstructured Supplementary Service Data</td></tr><tr><td>USSI</td><td>Unstructured Supplementary Service Data (USSD) using IP Multimedia (IM) Core Network (CN) subsystem (IMS)</td></tr><tr><td>USSI AS</td><td>USSI Application Server</td></tr><tr><td>VoIP</td><td>Voice Over IP</td></tr><tr><td>XCAP</td><td>XML Configuration Access Protocol</td></tr><tr><td>XML</td><td>eXtensible Markup Language</td></tr><tr><td>UDUB</td><td>User Determined User Busy</td></tr></table>

# 1.4.2 Terms

<table><tr><td>Term</td><td>Description</td></tr><tr><td>3GPP PS Data Off</td><td>A feature which when configured by the HPLMN and activated by the user prevents transport via PDN connections in 3GPP access of all IP packets except IP packets required by 3GPP PS Data Off Exempt Services, as defined in 3GPP Release 14 TS 22.011 [1]. Data Off can be activated only when the UE roams or regardless whether the UE roams or not, depending on UE implementation.</td></tr><tr><td>3GPP PS Data Off Exempt Services</td><td>A set of operator services that are allowed even if the 3GPP PS Data Off feature has been activated in the UE by the user, as defined in 3GPP Release 14 TS 22.011 [1].</td></tr><tr><td>3GPP PS Data Off status</td><td>Indicates state of usage of the 3GPP PS data off. 3GPP PS data off status at the UE can be either &quot;active&quot; or &quot;inactive&quot;, as defined in 3GPP Release 14 TS 24.229 [15].</td></tr><tr><td>Region</td><td>A part of a country, a country or a set of countries.</td></tr><tr><td>CallComposer</td><td>In this document, this term means the &quot;CallComposer service using the Multimedia Telephony session&quot; as defined of GSMA PRD RCC.20 [106].This service, when provided by the HPLMN, allows:• the originating UE to send one or more CallComposer Elements with a call invitation.• the terminating UE to accept CallComposer Elements received in a call invitation.</td></tr><tr><td>CallComposer Element</td><td>An information element set by the originating user for an outgoing call invitation and used by the terminating UE when notifying the user of an incoming call invitation. The following CallComposer Elements are defined:• importance,• subject,• picture,• location.The mapping of CallComposer Elements to SIP headers is as defined in section 2.4.4.2 of GSMA PRD RCC.20 [106].</td></tr></table>


1.5 Document Cross-References


<table><tr><td>Ref</td><td>Doc Number</td><td>Title</td></tr><tr><td>[1]</td><td>3GPP TS 22.011</td><td>Service Accessibility</td></tr><tr><td>[2]</td><td>3GPP TS 23.003</td><td>Numbering, addressing and identification</td></tr><tr><td>[3]</td><td>3GPP TS 23.167</td><td>IP Multimedia Subsystem (IMS) emergency sessions</td></tr><tr><td>[4]</td><td>3GPP TS 23.203</td><td>Policy and charging control architecture</td></tr><tr><td>[5]</td><td>3GPP TS 23.216</td><td>Single Radio Voice Call Continuity (SRVCC); Stage 2</td></tr><tr><td>[6]</td><td>3GPP TS 23.221</td><td>Architectural requirements</td></tr><tr><td>[7]</td><td>3GPP TS 23.228</td><td>IP Multimedia Subsystem (IMS); Stage 2</td></tr><tr><td>[8]</td><td>3GPP TS 23.237</td><td>IP Multimedia Subsystem (IMS) Service Continuity; Stage 2</td></tr><tr><td>[9]</td><td>3GPP TS 23.272</td><td>Circuit Switched (CS) fallback in Evolved Packet System (EPS); Stage 2</td></tr><tr><td>[10]</td><td>3GPP TS 23.401</td><td>General Packet Radio Service (GPRS) enhancements for Evolved Universal Terrestrial Radio Access Network (E-UTRAN) access</td></tr><tr><td>[11]</td><td>3GPP TS 24.008</td><td>Mobile radio interface layer 3 specification; Core Network protocols; Stage 3</td></tr><tr><td>[12]</td><td>3GPP TS 24.109</td><td>Bootstrapping interface (Ub) and network application function interface (Ua); Protocol details</td></tr><tr><td>[13]</td><td>3GPP TS 24.147</td><td>Conferencing using the IP Multimedia (IM) Core Network (CN) subsystem; Stage 3</td></tr><tr><td>[14]</td><td>3GPP TS 24.173</td><td>IMS Multimedia telephony service and supplementary services; Stage 3</td></tr><tr><td>[15]</td><td>3GPP TS 24.229</td><td>IP multimedia call control protocol based on Session Initiation Protocol (SIP) and Session Description Protocol (SDP); Stage 3</td></tr><tr><td>[16]</td><td>3GPP TS 24.237</td><td>IP Multimedia Subsystem (IMS) Service Continuity; Stage 3</td></tr><tr><td>[17]</td><td>3GPP TS 24.301</td><td>Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS); Stage 3</td></tr><tr><td>[18]</td><td>3GPP TS 24.305</td><td>Selective Disabling of 3GPP User Equipment Capabilities (SDoUE) Management Object (MO)</td></tr><tr><td>[19]</td><td>3GPP TS 24.341</td><td>Support of SMS over IP networks; Stage 3</td></tr><tr><td>[20]</td><td>3GPP TS 24.604</td><td>Communication Diversion (CDIV) using IP Multimedia (IM)Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>[21]</td><td>3GPP TS 24.605</td><td>Conference (CONF) using IP Multimedia (IM) Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>[22]</td><td>3GPP TS 24.606</td><td>Message Waiting Indication (MWI) using IP Multimedia (IM) Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>[23]</td><td>3GPP TS 24.607</td><td>Originating Identification Presentation (OIP) and Originating Identification Restriction (OIR) using IP Multimedia (IM) Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>[24]</td><td>3GPP TS 24.608</td><td>Terminating Identification Presentation (TIP) and Terminating Identification Restriction (TIR) using IP Multimedia (IM) Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>[25]</td><td>3GPP TS 24.610</td><td>Communication HOLD (HOLD) using IP Multimedia (IM) Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>[26]</td><td>3GPP TS 24.611</td><td>Anonymous Communication Rejection (ACR) and Communication Barring (CB) using IP Multimedia (IM) Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>[27]</td><td>3GPP TS 24.615</td><td>Communication Waiting (CW) using IP Multimedia (IM) Core Network (CN) subsystem; Protocol Specification</td></tr><tr><td>[28]</td><td>3GPP TS 24.623</td><td>Extensible Markup Language (XML) Configuration Access Protocol (XCAP) over the Ut interface for Manipulating Supplementary Services</td></tr><tr><td>[29]</td><td>3GPP TS 26.071</td><td>Mandatory speech CODEC speech processing functions; AMR speech Codec; General description</td></tr><tr><td>[30]</td><td>3GPP TS 26.073</td><td>ANSI C code for the Adaptive Multi Rate (AMR) speech codec</td></tr><tr><td>[31]</td><td>3GPP TS 26.090</td><td>Mandatory Speech Codec speech processing functions; Adaptive Multi-Rate (AMR) speech codec; Transcoding functions</td></tr><tr><td>[32]</td><td>3GPP TS 26.093</td><td>Mandatory speech codec speech processing functions Adaptive Multi-Rate (AMR) speech codec; Source controlled rate operation</td></tr><tr><td>[33]</td><td>3GPP TS 26.103</td><td>Speech codec list for GSM and UMTS</td></tr><tr><td>[34]</td><td>3GPP TS 26.104</td><td>ANSI-C code for the floating-point Adaptive Multi-Rate (AMR) speech codec</td></tr><tr><td>[35]</td><td>3GPP TS 26.114</td><td>IP Multimedia Subsystem (IMS); Multimedia telephony; Media handling and interaction</td></tr><tr><td>[36]</td><td>3GPP TS 26.131</td><td>Terminal acoustic characteristics for telephony; Requirements</td></tr><tr><td>[37]</td><td>3GPP TS 26.132</td><td>Speech and video telephony terminal acoustic test specification</td></tr><tr><td>[38]</td><td>3GPP TS 26.171</td><td>Speech codec speech processing functions; Adaptive Multi-Rate - Wideband (AMR-WB) speech codec; General description</td></tr><tr><td>[39]</td><td>3GPP TS 26.173</td><td>ANSI-C code for the Adaptive Multi-Rate - Wideband (AMR-WB) speech codec</td></tr><tr><td>[40]</td><td>3GPP TS 26.190</td><td>Speech codec speech processing functions; Adaptive Multi-Rate - Wideband (AMR-WB) speech codec; Transcoding functions</td></tr><tr><td>[41]</td><td>3GPP TS 26.193</td><td>Speech codec speech processing functions; Adaptive Multi-Rate - Wideband (AMR-WB) speech codec; Source controlled rate operation</td></tr><tr><td>[42]</td><td>3GPP TS 26.204</td><td>Speech codec speech processing functions; Adaptive Multi-Rate - Wideband (AMR-WB) speech codec; ANSI-C code</td></tr><tr><td>[43]</td><td>3GPP TS 27.007</td><td>AT command set for User Equipment (UE)</td></tr><tr><td>[44]</td><td>3GPP TS 31.103</td><td>Characteristics of the IP Multimedia Services Identity Module (ISIM) application</td></tr><tr><td>[45]</td><td>3GPP TS 33.203</td><td>3G security; Access security for IP-based services</td></tr><tr><td>[46]</td><td>3GPP TS 33.222</td><td>Generic Authentication Architecture (GAA); Access to network application functions using Hypertext Transfer Protocol over Transport Layer Security (HTTPS)</td></tr><tr><td>[47]</td><td>3GPP TS 36.101</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA); User Equipment (UE) radio transmission and reception</td></tr><tr><td>[48]</td><td>3GPP TS 36.104</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA); Base Station (BS) radio transmission and reception</td></tr><tr><td>[49]</td><td>3GPP TS 36.300</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA) and Evolved Universal Terrestrial Radio Access Network (E-UTRAN); Overall description; Stage 2</td></tr><tr><td>[50]</td><td>3GPP TS 36.321</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA); Medium Access Control (MAC) protocol specification</td></tr><tr><td>[51]</td><td>3GPP TS 36.323</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA); Packet Data Convergence Protocol (PDCP) specification</td></tr><tr><td>[52]</td><td>3GPP TS 36.331</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA);Radio Resource Control (RRC); Protocol specification</td></tr><tr><td>[53]</td><td>IETF RFC 768</td><td>User Datagram Protocol</td></tr><tr><td>[54]</td><td>IETF RFC 3095</td><td>RObust Header Compression (ROHC): Framework and four profiles: RTP, UDP, ESP, and uncompressed</td></tr><tr><td>[55]</td><td>IETF RFC 3261</td><td>SIP: Session Initiation Protocol</td></tr><tr><td>[56]</td><td>IETF RFC 3550</td><td>RTP: A Transport Protocol for Real-Time Applications</td></tr><tr><td>[57]</td><td>IETF RFC 3551</td><td>RTP Profile for Audio and Video Conferences with Minimal Control</td></tr><tr><td>[58]</td><td>IETF RFC 3556</td><td>Session Description Protocol (SDP) Bandwidth Modifiers for RTP Control Protocol (RTCP) Bandwidth</td></tr><tr><td>[59]</td><td>IETF RFC 3680</td><td>A Session Initiation Protocol (SIP) Event Package for Registrations</td></tr><tr><td>[60]</td><td>IETF RFC 3842</td><td>A Message Summary and Message Waiting Indication Event Package for the Session Initiation Protocol (SIP)</td></tr><tr><td>[61]</td><td>IETF RFC 4575</td><td>A Session Initiation Protocol (SIP) Event Package for Conference State</td></tr><tr><td>[62]</td><td>IETF RFC 4815</td><td>RObust Header Compression (ROHC): Corrections and Clarifications to RFC 3095</td></tr><tr><td>[63]</td><td>IETF RFC 4867</td><td>RTP Payload Format and File Storage Format for the Adaptive Multi-Rate (AMR) and Adaptive Multi-Rate Wideband (AMR-WB) Audio Codec</td></tr><tr><td>[64]</td><td>IETF RFC 5939</td><td>Session Description Protocol (SDP) Capability Negotiation</td></tr><tr><td>[65]</td><td>GSMA PRD IR.65</td><td>IMS Roaming and Interworking Guidelines</td></tr><tr><td>[66]</td><td>GSMA PRD IR.67</td><td>DNS/ENUM Guidelines for Service Providers and GRX/IPX Providers</td></tr><tr><td>[67]</td><td>GSMA PRD IR.88</td><td>LTE Roaming Guidelines</td></tr><tr><td>[68]</td><td>3GPP TS 24.167</td><td>3GPP IMS Management Object (MO); Stage 3</td></tr><tr><td>[69]</td><td>3GPP TS 36.322</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA); Radio Link Control (RLC) protocol specification</td></tr><tr><td>[70]</td><td>ITU-T Recommendation T.140</td><td>Protocol for multimedia application text conversation</td></tr><tr><td>[71]</td><td>3GPP TS 24.628</td><td>Common Basic Communication procedures using IP Multimedia (IM) Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>[72]</td><td>IETF RFC 4961</td><td>Symmetric RTP / RTP Control Protocol (RTCP)</td></tr><tr><td>[73]</td><td>IETF RFC 4745</td><td>Common Policy: A Document Format for Expressing Privacy Preferences</td></tr><tr><td>[74]</td><td>IETF RFC 5009</td><td>Private Header (P-Header) Extension to the Session Initiation Protocol</td></tr><tr><td>[75]</td><td>IETF RFC 4825</td><td>The Extensible Markup Language (XML) Configuration Access Protocol (XCAP)</td></tr><tr><td>[76]</td><td>3GPP TS 26.441</td><td>Codec for Enhanced Voice Services (EVS); General overview</td></tr><tr><td>[77]</td><td>3GPP TS 26.442</td><td>Codec for Enhanced Voice Services (EVS); ANSI C code (fixed-point)</td></tr><tr><td>[78]</td><td>3GPP TS 26.443</td><td>Codec for Enhanced Voice Services (EVS); ANSI C code (floating-point)</td></tr><tr><td>[79]</td><td>3GPP TS 26.445</td><td>Codec for Enhanced Voice Services (EVS); Detailed Algorithmic Description</td></tr><tr><td>[80]</td><td>3GPP TS 26.446</td><td>Codec for Enhanced Voice Services (EVS); AMR-WB Backward Compatible Functions</td></tr><tr><td>[81]</td><td>3GPP TS 26.447</td><td>Codec for Enhanced Voice Services (EVS); Error Concealment of Lost Packets</td></tr><tr><td>[82]</td><td>3GPP TS 26.449</td><td>Codec for Enhanced Voice Services (EVS); Comfort Noise Generation (CNG) Aspects</td></tr><tr><td>[83]</td><td>3GPP TS 26.450</td><td>Codec for Enhanced Voice Services (EVS); Discontinuous Transmission (DTX)</td></tr><tr><td>[84]</td><td>3GPP TS 26.451</td><td>Codec for Enhanced Voice Services (EVS); Voice Activity Detection (VAD)</td></tr><tr><td>[85]</td><td>3GPP TS 22.030</td><td>Man-Machine Interface (MMI) of the User Equipment (UE)</td></tr><tr><td>[86]</td><td>ITEF RFC 3840</td><td>Indicating User Agent Capabilities in the Session Initiation Protocol (SIP)</td></tr><tr><td>[87]</td><td>3GPP TS 24.629</td><td>Explicit Communication Transfer (ECT) using IP Multimedia (IM) Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>[88]</td><td>3GPP TS 24.166</td><td>3GPP IP Multimedia Subsystem (IMS) conferencing Management Object (MO)</td></tr><tr><td>[89]</td><td>IETF RFC 3262</td><td>Reliability of Provisional Responses in the Session Initiation Protocol (SIP)</td></tr><tr><td>[90]</td><td>3GPP TS 24.417</td><td>Management Object (MO) for Originating Identification Presentation (OIP) and Originating Identification Restriction (OIR) using IP Multimedia (IM) Core Network (CN) subsystem</td></tr><tr><td>[91]</td><td>3GPP TS 24.424</td><td>Management Object (MO) for Extensible Markup Language (XML) Configuration Access Protocol (XCAP) over the Ut interface for Manipulating Supplementary Services</td></tr><tr><td>[92]</td><td>GSMA PRD TS.32</td><td>Technical Adaptation of Devices through Late Customisation</td></tr><tr><td>[93]</td><td>GSMA PRD RCC.14</td><td>Service Provider Device Configuration</td></tr><tr><td>[94]</td><td>IETF RFC 4122</td><td>Universally Unique IDentifier (UUID) URN Namespace</td></tr><tr><td>[95]</td><td>3GPP TS 24.275</td><td>Unstructured Management Object (MO) for Basic Communication Part (BCP) of IMS Multimedia Telephony (MMTEL) communication service</td></tr><tr><td>[96]</td><td>3GPP TS 24.368</td><td>Non-Access Stratum (NAS) Configuration Management Object (MO)</td></tr><tr><td>[97]</td><td>3GPP TS 23.090</td><td>Unstructured Supplementary Service Data (USSD); Stage 2</td></tr><tr><td>[98]</td><td>3GPP TS 24.390</td><td>Unstructured Supplementary Service Data (USSD) using IP Multimedia (IM) Core Network (CN) subsystem IMS; Stage 3</td></tr><tr><td>[99]</td><td>3GPP TS 24.391</td><td>Unstructured Supplementary Service Data (USSD) using IP Multimedia (IM) Core Network (CN) subsystem (IMS) Management Object (MO)</td></tr><tr><td>[100]</td><td>OMA-ERELD-DM-V1_2</td><td>Enabler Release Definition for OMA Device Management, Version 1.2</td></tr><tr><td>[101]</td><td>3GPP TS 37.340</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA) and NR; Multi-connectivity</td></tr><tr><td>[102]</td><td>3GPP TS 38.331</td><td>NR;Radio Resource Control (RRC); Protocol Specification</td></tr><tr><td>[103]</td><td>GSMA PRD RCC.07</td><td>Rich Communication Suite 8.0 Advanced Communications Services and Client Specification</td></tr><tr><td>[104]</td><td>IETF RFC 7852</td><td>Additional Data Related to an Emergency Call</td></tr><tr><td>[105]</td><td>IETF RFC 6228</td><td>Session Initiation Protocol (SIP) Response Code for Indication of Terminated Dialog</td></tr><tr><td>[106]</td><td>GSMA PRD RCC.20</td><td>Enriched Calling Technical Specification</td></tr></table>

# 2 IMS Feature Set

# 2.1 General

The IMS profile part lists the mandatory capabilities, that are required over the Gm and Ut reference points. 

# 2.2 Support of generic IMS functions

# 2.2.1 SIP Registration Procedures

The UE and the IMS core network must follow the Session Initiated Protocol (SIP) registration procedures defined in 3GPP TS 24.229 [15]. In addition, when the conditions for performing IMS registration in bullets 2, 3, 4, 5 and 6 in section L.3.1.2 of 3GPP TS 24.229 

[15] evaluate to true, then the UE must register with the IMS. Selective Disabling of 3GPP User Equipment Capabilities as defined in 3GPP TS 24.305 [18] is not mandated in this profile, therefore in the case where 3GPP TS 24.305 [18] Managed Object (MO) is not deployed, it is assumed that IMS is enabled in the terminal and the IMS parameter is set to the value "enabled" as specified in Annex C.3. 

Note 1: UE registering with IMS in other situations is possible. 

The home operator can configure the UE with Media_type_restriction_policy for non-roaming and for roaming case, SMSoIP_usage_policy and RegRetryBaseTime and RegRetryMaxTime parameters as specified in Annex C.3. 

The UE must include IMS Communication Service Identifier (ICSI) value used to indicate the IMS Multimedia Telephony service, that being urn: urn-7:3gpp-service.ims.icsi.mmtel per 3GPP TS 24.173 [14], using procedures as defined in section 5.1.1.2.1 of 3GPP TS 24.229 [15]. The UE must also include the feature tag used to indicate SMS over IP service (see section 2.5 and A.7), that being +g.3gpp.smsip as defined in section 5.3.2.2 of 3GPP TS 24.341 [19]. If the UE is a Session Continuity UE (SC-UE) (e.g. due to support of SR-VCC as described in Annex A.3), then the UE must include the g.3gpp.accesstype media feature tag as specified in section 6.2.2 of Release 11 of 3GPP TS 24.237 [16]. If the Call Composer service is enabled, then the UE must include the +g.gsma.callcomposer media feature tag as defined in GSMA PRD RCC.20 [106]. 

The UE must include the audio media feature tag, as defined in IETF RFC 3840 [86], in the Contact header field of the SIP REGISTER request, using procedures of 3GPP TS 24.229 [15]. 

The UE and the IMS core network must support network-initiated de-registration as defined in 3GPP TS 24.229 [15]. 

The UE must subscribe to the registration event package as defined in section 5.1.1.3 of 3GPP TS 24.229 [15]. 

The UE must include an IMEI URN (see 3GPP TS 23.003 [2] section 13.8) in the "+sip.instance" header field parameter (Instance ID) of the contact address. 

As stated in Release 14 of 3GPP TS 24.229 [15], the UE must include a user part in the URI of the contact address such that the user part is globally unique and does not reveal any private information. 

Note 2: To generate this user part, the UE can use a time-based UUID (Universal Unique Identifier) generated as per subclause 4.2 of IETF RFC 4122 [94]. 

All IMS public user identities provided in the implicit registration set used for VoLTE by the IMS core network must be alias user identities and must include a tel URI (Uniform Resource Identifier). The following public user identity must be assigned to the implicit registration set used for VoLTE and it must be used by the UE when registering for VoLTE: 

a) When ISIM is used, the public user identity in the first (or only) record in the Elementary File in the ISIM (see 3GPP TS 31.103 [44] section 4.2.4); or 

b) The temporary public user identity derived from the IMSI (3GPP TS 24.229 [15]). 

No other implicit registration set must be used for VoLTE. 

Note 3: According to 3GPP TS 23.228 [7], a public user identity is an alias of another public user identity if both identities belong to the same implicit registration set, are linked to the same service profile and have the same service data configured for every service. 

The UE must set the URI of the From header field of the REGISTER request, for userinitiated reregistration or for user-initiated deregistration, to the public user identity which was used in the URI of the From header field of the REGISTER request that created the binding being refreshed or being removed. The UE must set the URI of the To header field of the REGISTER request, for user-initiated reregistration and for user-initiated deregistration, to the public user identity that was used in the URI of the To header field of the REGISTER request that created the binding being refreshed or being removed. 

Note 4: The "tag" header field parameter can differ in the From header field and in the To header field for the different REGISTER requests. 

For backwards compatibility the network must support all formats of URIs compliant with 3GPP TS 24.229 [15]. 

The UE must perform a re-registration prior to the expiry time of the existing registration as described in section 5.1.1.4.1 of 3GPP TS 24.229 [15]. 

If the UE receives a SIP 305 (Use Proxy) response to a re-registration, then the UE must acquire a P-CSCF different from the currently used P-CSCF and initiate a new initial registration as described in section 5.1.1.4.1 of 3GPP TS 24.229 [15]. If the UE receives a SIP 503 (Service Unavailable) response without a Retry-After header field, the SIP 503 (Service Unavailable) response must be treated as a SIP 500 (Server Internal Error) response (as stated in IETF RFC 3261 [55]) and the UE must initiate a new initial registration as described in section 5.1.1.4.1 of 3GPP TS 24.229 [15]. For the new initial registration, the UE must select a different P-CSCF from the P-CSCF list received from last PCO if not all of them have been attempted, otherwise the UE must re-establish a new PDN connection to the IMS well-known APN and get a new list of P-CSCFs (as stated in section 4.4) and choose from one of these P-CSCFs, as specified in section 5.1.1.4.1 of 3GPP TS 24.229 [15]. 

If the UE receives a SIP 503 (Service Unavailable) response or any other SIP 4xx, 5xx or 6xx response with Retry-After header as a response to an initial SIP REGISTER request, then the UE must re-attempt an initial registration via the same P-CSCF after the amount of time indicated in the Retry-After header field has expired or must immediately re-attempt an initial registration (as described above) when another P-CSCF is used. 

Note 5: The above condition assumes that the UE has IP connectivity when the UE re-attempts an initial registration. 

# 2.2.2 Authentication

The UE and the IMS core network must follow the procedures defined in 3GPP TS 24.229 [15] and 3GPP TS 33.203 [45] for authentication with IMS Authentication and Key Agreement (IMS-AKA), Sec-Agree and IPsec. Support of integrity protection is mandatory for 

both UE and network. Support of confidentiality protection is optional in the network, considering that lower layer security is available. 

The IMS core network must support the procedures for IM Services Identity Module (ISIM) based authentication. Support for ISIM based authentication in the UE is mandatory. 

The UE and IMS core network must support the procedures for USIM based authentication if there is no ISIM present on the Universal Integrated Circuit Card (UICC) as defined in Annex E.3.1 of 3GPP TS 23.228 [7] and Annex C.2 of 3GPP TS 24.229 [15]. This includes support for the P-Associated-URI header to handle barred IMS Public User Identities (IMPUs). 

The UE and the IMS core network must support the procedures for authentication at the Ut reference point as specified in 3GPP TS 24.623 [28]. 

The UE must and the IMS core network can support the procedures for authentication at the HTTP Content Server as defined in section 3.2.5.3 of GSMA PRD RCC.07 [103]. If the UE supports the OpenID Connect procedures for the HTTP Content Server as defined in GSMA PRD RCC.07 [103], then the UE must support the user authentication via HTTP embedded EAP-AKA for the authentication with the OpenID Connect authorization endpoint as defined in GSMA PRD RCC.14 [93]. 

If the UE supports the Generic Authentication Architecture procedures specified in 3GPP TS 24.623 [28], 3GPP TS 33.222 [46] and 3GPP TS 24.109 [12], then the UE must construct the Bootstrapping Server Function (BSF) address as defined in section 16.2 of 3GPP TS 23.003 [2]. 

Note 1: It is recommended that the UE supports the Generic Authentication Architecture procedures specified in 3GPP TS 24.623 [28], 3GPP TS 33.222 [46] and 3GPP TS 24.109 [12]. 

The UE must support receiving an HTTP 2xx response to HTTP requests for XCAP and the HTTP Content Server without being challenged by an HTTP 401 (Unauthorized) response. 

Note 2: The above authentication scenario is possible only if the APN used for HTTP for XCAP and HTTP Content Server traffic (see section 4.3.1) is routed to the home network. The home network is able to authenticate the UE without challenging the UE for Ut authentication. 

Note 3: The above authentication scenario is applicable for the HTTP Content Server if the Call Composer service is enabled, and no values are provided for the configuration parameters FT HTTP CS USER and FT HTTP CS PWD (see section C.3), and authentication via HTTP embedded AKA or the Generic Authentication Architecture is not available. 

# 2.2.3 Addressing

# 2.2.3.1 Public User Identities

The UE and IMS core network must support Public User Identities as defined in section 13.4 of 3GPP TS 23.003, which includes all of the following types of addresses: 

 Alphanumeric SIP-URIs 

 Example: sip:voicemail@example.com 

 MSISDN represented as a SIP URI: 

 Example: sip:+447700900123@example.com;user=phone 

 MSISDN represented as a tel URI: 

 Example: tel:+447700900123 

Note: Further requirements for support of Public User Identities in the network are specified in IR.65 [65]. 

# 2.2.3.2 Local numbers

The UE and IMS core network must support local numbers as defined in Alternative 2 in Sections 5.1.2A.1.3 and 5.1.2A.1.5 in 3GPP TS 24.229 [15]. That is, the UE must set the dial string containing the local number to the user part of SIP URI in the Request URI, and set the "user=phone" parameter, with the "phone-context" tel URI parameter to the user part. 

The UE and network must support home-local numbers and geo-local numbers. The UE must set the "phone-context" parameter as defined in sections 5.1.2A.1.5 and 7.2A.10 in 3GPP TS 24.229 [15]: 

for home local numbers the UE must set the "phone-context" parameter to the home domain name, as it is used to address the SIP REGISTER request. 

Example of phone-context for home-local number: if the home network domain used in SIP REGISTER R-URI is "ims.mnc026.mcc567.3gppnetwork.org" then the "phone context" parameter is set to the same string. 

for geo-local numbers the UE must set the "phone-context" parameter with additional visited network information when available. 

Example of phone-context for geo-local number: if the visited network has MCC = 234, MNC = 15, and the home network has MCC = 567, MNC = 26, the "phone context" parameter is set to the string 

"234.15.eps.ims.mnc026.mcc567.3gppnetwork.org". 

Note 1: The UE on E-UTRAN knows the access information and hence the "phonecontext" can be set accordingly. 

If the local number type is not explicitly indicated by the user in outgoing voice calls to either geo-local or home-local numbers, then the UE must use the Policy_on_local_numbers parameter as specified in Annex C.3 to determine the local number type. For outgoing SMS messages to local numbers, the UE must use home-local numbers. 

Note 2: SMS does not currently specify how to route messages to a VPLMN for onward routing to a destination, therefore, outgoing SMS messages cannot be destined to geo-local numbers. 

# 2.2.3.3 Other addressing related SIP header fields

The UE and IMS core network must support the P-Called-Party-ID header field; the network must use this header field as defined in 3GPP TS 24.229 [15]. 

The support of Globally Routable User agent URIs (GRUUs) by UE or network is not required. 

# 2.2.4 Call Establishment and Termination

The UE and the IMS core network must follow 3GPP TS 24.229 [15] for establishment and termination of a call. 

The UE and the IMS core network must support reliable provisional responses as defined in IETF RFC 3262 [89]. The UE must support reliable SIP 18x policy and procedures as specified in section 5.1.4.1 of 3GPP Release 14 TS 24.229 [15]. 

The home operator can configure the UE with Timer_T1, Timer_T2 and Timer_T4 parameter as specified in Annex C.3. 

The UE must be able to accept a SIP INVITE request without a Session Description Protocol (SDP) offer and the UE must include a SDP offer with audio media in the first non-failure reliable response to a SIP INVITE request without SDP offer. 

Note 1: Other media can be included in the SDP offer in the first non-failure reliable response. 

The UE must include the audio media feature tag, as defined in IETF RFC 3840 [86], in the Contact header field of the SIP INVITE request, and in the Contact header field of the SIP response to the SIP INVITE request, as specified in 3GPP TS 24.229 [15]. 

The UE must indicate in the SDP of the initial INVITE that the audio media is send-receive i.e. either by including the direction attribute "a $\left[ = \right.$ sendrecv" or by omitting the direction attributes. If the UE receives an initial INVITE that contains "a=sendrecv" or no direction attribute in the SDP offer, the UE must indicate "a $\left[ = \right.$ sendrecv" or no direction attribute in the SDP answer, regardless of the use of SIP preconditions framework or of the resource reservation status. 

Note 2: Previous versions of 3GPP TS 24.229 [15] mandated the use of the SDP inactive attribute. 3GPP Release 12 TS 24.229 [15] does not prohibit specific services from using direction attributes to implement their servicespecific behaviours. 

For the purpose of indicating an IMS communication service to the network, the UE must use an ICSI value in accordance with 3GPP TS 24.229 [15]. The ICSI value used must indicate the IMS Multimedia Telephony service, which is urn:urn-7:3gppservice.ims.icsi.mmtel, as specified in 3GPP TS 24.173 [14]. 

If the Call Composer service is enabled, then the UE must include the media feature tag for the Call Composer in the Contact header field of the SIP INVITE request, and in the Contact header field of the SIP response to the SIP INVITE request, as specified in section 2.4.4 of GSMA PRD RCC.20 [106]. 

If the Call Composer service is enabled, then the UE must include in the SIP INVITE request the header fields for Call Composer elements as defined in section 2.4.4.2 of GSMA PRD RCC.20 [106]. 

If the Call Composer service is enabled and the UE receives in an incoming SIP INVITE request header fields for Call Composer Elements as defined in section 2.4.4.2 of GSM PRD RCC.20 [106], then the UE must process the header fields as defined in section 2.4.4.3 and 2.4.4.5 of GSMA PRD RCC.20 [106]. 

If the Call Composer service is not enabled, then the UE must ignore any Call Composer Elements in the incoming INVITE request. 

The usage of preconditions is discussed in Section 2.4. 

If the user rejects an incoming call by invoking User Determined User Busy (UDUB) as described in 3GPP TS 22.030 [85], then the UE must send a SIP 486 (Busy here) response to the network. 

Note 3: The appropriate SIP response to reject a call on all devices for a multipledevice scenario and operator and vendor specific services are out-of-scope of this document. 

When the UE sends a CANCEL or BYE request, the UE must include a Reason header field with a protocol value set to "RELEASE_CAUSE" and follow the procedures specified in sections 5.1.3.1 and 5.1.5 of 3GPP Release 14 TS 24.229 [15]. 

# 2.2.5 Forking

Forking in the network is outside the scope of the present document. However, for interoperability and forward-compatibility reasons, the UE must be ready to receive responses generated due to a forked request and behave according to the procedures specified in IETF RFC 3261 [55], section 4.2.7.3 of 3GPP TS 23.228 [7], 3GPP TS 24.229 [15] and section 4.7.2.1 of 3GPP Release 13 TS 24.628 [71]. Furthermore, the UE should be able to maintain at least forty (40) parallel early dialogs until receiving the final response on one of them and the UE must support receiving media on one of these early dialogs. 

If the originating UE needs to release an early dialog, the UE must send a BYE request within the early dialog to be released, in accordance with section 15 in IETF RFC 3261 [55], e.g. when the UE receives the first response that would create an early dialog it cannot maintain, the UE sends a BYE request on that early dialog without saving dialog data. 

It is also possible that the network or the terminating UE will need to release an early dialog using the 199 (Early Dialog Terminated) response defined in IETF RFC 6228 [105]. To support this, the originating UE must include the "199" option tag in the Supported header field in the initial INVITE request and must understand a 199 (Early Dialog Terminated) response code and act as specified in section 5.1.3.1 of 3GPP TS 24.229 [15]. 

Note 1: An early dialog that is maintained is one where a SIP 18x response has been received and the early dialogue has not been terminated (e.g. by receipt of a SIP 199 response) prior to receiving a SIP 2xx response. 

Note 2: Multiple early dialogs can occur as a result of forking or for other reasons such as announcements or services. 

The IMS core network can support sending and the UE must support receiving a SIP CANCEL request including a Reason header field with values of: 

 SIP; cause=200; text="Call completed elsewhere" 

 SIP; cause $\mathtt { \Lambda } = 6 0 3$ ; tex $\cdot = "$ Declined" 

 SIP; cause $\mathtt { \Lambda } = 6 0 0$ ; text $\mathbf { \lambda } = \mathbf { \lambda } ^ { \prime }$ "Busy Everywhere" 

for forked calls as defined in 3GPP Release 12 TS 24.229 [15]. 

# 2.2.6 The use of Signalling Compression

The UE must not use SIGCOMP when the initial IMS registration is performed in E-UTRAN access as specified in Release 10 3GPP TS 24.229 [15]. 

Note: Although this version of the profile focuses on E-UTRAN, if the initial IMS registration occurs in other IP Connectivity Accesses then SIGCOMP can be used by the UE. 

# 2.2.7 Early media and announcements

The UE must behave as specified in section 4.7.2.1 of 3GPP Release 13 TS 24.628 [71]. 

In addition, the UE must support the P-Early-Media header field as defined in IETF RFC 5009 [74], and must include a P-Early-Media header field with the "supported" parameter to initial INVITE requests it originates as specified in section 5.1.3.1 of 3GPP TS 24.229 [15]. 

The UE must also maintain an early media authorization state per dialog as described in IETF RFC 5009 [74]. 

As stated in 3GPP TS 24.628 [71], the UE must render locally generated communication progress information, if: 

an early dialog exists where a SIP 18x response to the SIP INVITE request other than 183 (Session Progress) response was received; 

no early dialog exists where the last received P-Early-Media header field as described in IETF RFC 5009 [12] contained "sendrecv" or "sendonly"; and 

 in-band information is not received from the network. 

The UE must evaluate the above rules again after each subsequent request or response received from the remote party, and when in-band information starts, and when the UE determines the in-band media to have stopped. 

Note 1: A SIP request or response received without a P-Early-Mediaheader does not change the early media authorization state for the early dialog on which it was received. 

Note 2: In-band information arriving at the UE will always override locally generated communication progress information as defined in section 4.7.2.1 of TS 24.628 [71]. 

# 2.2.8 SIP Session Timer

The UE must support and use IETF RFC 4028 [86] as follows: 

for an initial SIP INVITE request, the UE must include a Supported header with the option tag "timer" and must either insert Session-Expires header field with the deltaseconds portion set to 1800, or must not include the Session-Expires header field in the initial SIP INVITE request; 

if the UE receives a SIP 422 response to an INVITE request, the UE must follow the procedures of section 7.4 in IETF RFC 4028 [86]; 

it is recommended that the UE does not include the "refresher" parameter in the Session-Expires header field of the SIP INVITE request. If the UE includes the "refresher" parameter in the Session-Expires header field of the SIP INVITE request, the UE must set the "refresher" parameter to "uac"; 

 if a received SIP INVITE request indicates support of the "timer" option tag, and does not contain the Session-Expires header field, the UE must include a Session-Expires header field with the delta-seconds portion set to the greater of 1800 or the value contained in the Min-SE header (if present in the received INVITE) and the "refresher" parameter with the value "uac" in SIP 2xx response to the SIP INVITE request; and 

if a received SIP INVITE request indicates support of the "timer" option tag, and contains the Session-Expires header field without "refresher" parameter, the UE must include the "refresher" parameter with the value "uac" in the Session-Expires header field of the SIP 2xx response to the SIP INVITE request, and must set the deltaseconds portion of the Session-Expires header field of the SIP 2xx response to the SIP INVITE request to the value indicated in the delta-seconds portion of the Session-Expires header field of the SIP INVITE request. 

Note: The network can choose to influence the session timer negotiation by modifying any of the related header fields or header field parameters within the constraints of IETF RFC 4028 [86]. 

# 2.2.9 SIP OPTIONS

A Contact header field in a SIP OPTIONS request and in the 200 OK response to a SIP OPTIONS request must include the IMS Communication Service Identifier (ICSI) value of "urn:urn-7:3gpp-service.ims.icsi.mmtel", as defined in 3GPP TS 24.173 [14]. 

If the Call Composer service is enabled, then a Contact header field in SIP OPTIONS request and in the 200 OK response to a SIP OPTIONS request must include the media feature tag for Call Composer as defined in GSMA PRD RCC.20 [106]. 

# 2.3 Supplementary Services

# 2.3.1 Supplementary Services Overview

Supplementary services must be supported as defined as part of 3GPP MMTel TS 24.173 [14], with the constraints described in this section. 

The UE and the Telephony Application Server (TAS) must support the supplementary services listed in Table 2.1. The provisioning of these supplementary services for a subscriber is optional and is an operator decision. 

<table><tr><td>Supplementary Service</td></tr><tr><td>Originating Identification Presentation 3GPP TS 24.607 [23]</td></tr><tr><td>Terminating Identification Presentation 3GPP TS 24.608 [24]</td></tr><tr><td>Originating Identification Restriction 3GPP TS 24.607 [23] (Note 1)</td></tr><tr><td>Terminating Identification Restriction 3GPP TS 24.608 [24] (Note 1)</td></tr><tr><td>Communication Forwarding Unconditional 3GPP TS 24.604 [20] (Note 1)</td></tr><tr><td>Communication Forwarding on not Logged in 3GPP TS 24.604 [20] (Note 1)</td></tr><tr><td>Communication Forwarding on Busy 3GPP TS 24.604 [20] (Note 1)</td></tr><tr><td>Communication Forwarding on not Reachable 3GPP TS 24.604 [20] (Note 1)</td></tr><tr><td>Communication Forwarding on No Reply 3GPP TS 24.604 [20] (Note 1)</td></tr><tr><td>Barring of All Incoming Calls 3GPP TS 24.611 [26] (Note 1)</td></tr><tr><td>Barring of All Outgoing Calls 3GPP TS 24.611 [26] (Note 1)</td></tr><tr><td>Barring of Outgoing International Calls 3GPP TS 24.611 [26] (Note 2)</td></tr><tr><td>Barring of Outgoing International Calls - ex Home Country 3GPP TS 24.611 [26] (Note 2)</td></tr><tr><td>Barring of Outgoing International Calls - When Roaming 3GPP TS 24.611 [26] (Note 2)</td></tr><tr><td>Barring of Incoming Calls - When Roaming 3GPP TS 24.611 [26] (Note 1)</td></tr><tr><td>Communication Hold 3GPP TS 24.610 [25]</td></tr><tr><td>Message Waiting Indication 3GPP TS 24.606 [22] (Note 1)</td></tr><tr><td>Communication Waiting 3GPP TS 24.615 [27] (Note 1)</td></tr><tr><td>Ad-Hoc Multi Party Conference 3GPP TS 24.605 [21] (Note 1)</td></tr><tr><td>Explicit Communication Transfer - Consultative 3GPP TS 24.629 [87] (Note 1)</td></tr></table>


Table 2.1 Supplementary services


Note 1: Recommended options are described in sections 2.3.3 – 2.3.12. 

Note 2: Barring of International Calls is a 3GPP Release 9 feature. 

The UE must and the network can support the Call Composer service. The provisioning of the Call Composer service for a subscriber is optional and is an operator decision. 

Note 3: Support of other supplementary services is out of scope of this document. 

# 2.3.2 Supplementary Service Configuration

For supplementary service configuration, the UE and IMS core network must support XCAP at the Ut reference point as defined in 3GPP TS 24.623 [28]. 

The home operator can configure the UE with the "XCAP Root URI" parameter as specified in Annex C.3 with an XCAP root URI as specified in 3GPP TS 24.623 [28]. If the UE has not been configured with an XCAP root URI, then the UE must construct an XCAP root URI as defined in section 13.9 of 3GPP TS 23.003 [2]. 

As XCAP User Identity (XUI) the UE must use the default public user identity received in P-Associated-URI header in the SIP 200 (OK) response for REGISTER. 

When not registered with IMS, the UE must use the default public user identity received during the last successful registration as in Section 2.2.1 in this document. 

If the UE receives an HTTP 404 (Not Found) response when attempting to access the entire simservs XML document (i.e. a node selector is not included in the Request-URI of the XCAP request), or the UE does not have a stored default public user identity, then: 

if the UE has an ISIM, then the UE must use the public user identity in the first (or only) record in the EFIMPU Elementary File in the ISIM (see section 4.2.4 of 3GPP TS 31.103 [44]) as XUI in further XCAP requests sent until the next successful IMS registration. 

if the UE has a USIM but not an ISIM, then the UE must use the temporary public user identity derived from the IMSI (see section 13.4B of 3GPP TS 23.003 [2]) as XUI in further XCAP requests sent until the next successful IMS registration. 

Note 1: If the UE attempts to access a fragment of the simservs XML document (i.e. a node selector is included in the Request-URI of the XCAP request), and the UE receives a HTTP 404 (Not Found) response, the UE is allowed to continue attempting to access the simservs XML document. If the UE continues to receive a HTTP 404 (Not Found) response when attempting to access a fragment of the simservs XML document, the UE can attempt to access the entire simservs XML document to determine if the XUI is valid. 

Note 2: If the XUI is derived from the IMPU stored on the ISIM or derived from the temporary IMPU, then the UE does not share such XUI with another UE in order to prevent the revealing of a potentially barred IMPU. 

The UE must configure settings of one supplementary service only per XCAP request. If the supplementary service to be configured contains a <ruleset> element with multiple <rule> elements as defined in IETF RFC 4745 [73] (e.g. as for Communication Diversion (CDIV), Communication Barring (CB)), then the UE must modify at most one <rule> element of the supplementary service per XCAP request. 

The UE must perform HTTP PUT and HTTP DELETE as conditional operations using the If-Match header field as defined in section 7.11 of IETF RFC 4825 [75]. 

When modifying a supplementary service, if there is an existing matching <rule> element, the UE must modify the child elements of the existing <rule> element. Otherwise, if no matching <rule> element is found, the UE must consider that the supplementary service is not provisioned for the user and must not insert a new <rule> element with a rule ID different from any existing rule ID in the XML document. 

Note 3: For each supplementary service that is provisioned for the user, the home operator needs to provide the matching <rule> element in the initial XML document. 

When deactivating a <rule> element for a supplementary service, and if there is a matching <rule> element without <rule-deactivated> condition, the UE must insert the <ruledeactivated> condition in the <conditions> element of the <rule> element. 

A <rule> element matches a supplementary service if: 

1. the supplementary service requires a <conditions> element, and the conditions (with exception of the <rule-deactivated> condition) included in the <conditions> element of the <rule> element are the same as the conditions of the <conditions> element required by the supplementary service; or 

2. the supplementary service does not require a <conditions> element and the <rule> element: 

 does not contain a <conditions> element; 

 contains an empty <conditions> element; or 

 contains a <conditions> element containing solely the <rule-deactivated> condition. 

The UE must not remove a <rule> element of a supplementary service profiled in this document. 

# 2.3.3 Ad-Hoc Multi Party Conference

The UE and the IMS core network must support the procedures defined in 3GPP TS 24.605 [21] and clause 5.3.1.3.2 of 3GPP Release 10 TS 24.147 [13], with the clarifications defined in this sub section. 

Note 1: As per section 4.2 of 3GPP TS 24.605 [21], the invocation and operation for conferencing is described in 3GPP TS 24.147 [13]. 

For conference creation, the UE and the IMS core network must support Three Way Session creation as described in section 5.3.1.3.3 of 3GPP TS 24.147 [13]. The UE must apply option 2b) when inviting the remote user to the conference. If the UE has not been configured with Conf_Factory_URI parameter as specified in Annex C.3, then the UE must construct the "Default Conference Factory URI for MMTel" as specified in clause 13.10 of 3GPP Release 12 TS 23.003 [2]. 

The UE can and the IMS core network must support the procedures in 3GPP TS 24.605 [21] for subscription to conference state events. The SIP SUBSCRIBE to conference state events must be sent outside the SIP INVITE dialog between the UE and the conference server. If the SUBSCRIBE request outside the existing INVITE dialog is rejected by a SIP 403 (Forbidden) response, the UE must send a SUBSCRIBE request in the existing INVITE dialog, as specified in clause 5.3.1.2 of 3GPP Release 12 TS 24.147 [13]. The UE is recommended to send the SUBSCRIBE request in the INVITE dialog until the next initial IMS registration. 

To ensure compatibility with UEs compliant with older versions of this specification the IMS core network must support SUBSCRIBE requests received within an INVITE dialog. The IMS core network can support all, or a subset of the elements and attributes specified in IETF RFC 4575 [61]. As a minimum, the IMS core network must support the following elements and attributes: 

 Conference-info: entity 

 Maximum-user-count 

 Users 

 User: entity 

 Display-text 

 Endpoint: entity 

 Status (supported values: connected, disconnected, on-hold) 

If the Display-text is not available for a conference participant, the IMS core network should provide the same value for the <User: Entity> and <Display-Text> fields. 

Note 2: This behaviour will enable all participants of the conference to be uniquely distinguished from each other. 

When inviting other users to a conference, the UE and the IMS core network must support the procedure described in section 5.3.1.5.3 of 3GPP TS 24.147 [13]. The UE must send the SIP REFER method by using the existing dialog for a conference session between the UE and the IMS core network (conference server). 

The UE must add the Replaces header to the Refer-to header field in the SIP REFER request, as described in section 5.3.1.5.3 of 3GPP TS 24.147 [13]. 

Note 3: In Three-Way session creation procedures, the UE has an existing session with the SIP REFER target. 

If the UE has subscribed to the conference event package, the UE must wait for the related SIP NOTIFY confirming the last invited participant and its identity before inviting a new participant. 

The UE and the IMS core network must support audio media for the conference session. 

Note 4: Support of other media types is out of scope of the document. 

Floor control for conferencing as described in section 8 of 3GPP TS 24.147 [13] is not required. 

Consent procedures for list server distribution as described in section 5.3.1.7 of 3GPP TS 24.147 [13] are not required. 

The conference server should send notification for Conference Event Package immediately and, in any case, within 5 seconds. 

# 2.3.4 Communication Waiting

The UE and the IMS core network must support the terminal based service, as described in 3GPP TS 24.615 [27]. The network-based service is not required. The Communication Waiting (CW) indication as defined in section 4.4.1 of 3GPP TS 24.615 [27] is not required. The UE is required to support Alert-Info, with values as specified in 3GPP TS 24.615 [27].The UE must provide the ability for the user to activate, deactivate and interrogate the terminal based service without using UE-to-network signalling (e.g. XCAP/Ut). 

# 2.3.5 Message Waiting Indication

The UE must and the IMS core network can support the Message Waiting Indication (MWI) event package, as defined in 3GPP TS 24.606 [22] and IETF RFC 3842 [60]. 

# 2.3.6 Originating Identification Restriction

The UE and the IMS core network must support the SIP procedures in 3GPP TS 24.607 [23]. Service configuration as described in Section 4.10 of 3GPP TS 24.607 [23], is not required. 

# 2.3.7 Terminating Identification Restriction

The UE and the IMS core network must support the SIP procedures in 3GPP TS 24.608 [24]. Service configuration, as described in section 4.9 of 3GPP TS 24.608 [24], is not required. 

# 2.3.8 Communication Diversion

The UE and the IMS core network must support the SIP procedures described in 3GPP TS 24.604 [20] for Communication Diversion (CDIV). For CDIV service activation, deactivation, and interrogation (XCAP operations), the UE and the IMS core network must support the XML rules for Call Forwarding Unconditional and the conditions, actions and elements listed in Table 2.2. However, the operator decides which rules are included in the XML document, e.g. depending on the subscription. The UE must handle a missing rule as defined in section 2.3.2. 

The UE and the IMS core network must support the XML rules as described in section 4.9.1 of 3GPP TS 24.604 [20]. The UE must support the History-Info header for identification of diverting parties at the terminating side and for identification of diverted-to parties at the originating side. At the terminating side, a History-Info entry must be used for the identification of the diverting party and that the call has been diverted only if another History-Info entry exists that has assigned the next index in sequence and includes a cause value in a cause-param SIP URI parameter as described in section 4.5.2.6.2 of 3GPP TS 24.604 [20]. At the originating side only History-Info entries including a cause value must be used for presentation of the diverted-to party. 

Note 1: The UE can deduce that the received call is a diverted call based on the cause-param values. 

Note 2: Support of subscription options and other conditions and actions are out of scope of the document. 

<table><tr><td>Type</td><td>Parameter</td></tr><tr><td>Rule containing condition</td><td>Busy</td></tr><tr><td>Rule containing condition</td><td>media (supported media types: audio, audio AND video)</td></tr><tr><td>Rule containing condition</td><td>no-answer</td></tr></table>

<table><tr><td>Type</td><td>Parameter</td></tr><tr><td>Rule containing condition</td><td>not-registered</td></tr><tr><td>Rule containing condition</td><td>not-reachable (Note 3)</td></tr><tr><td>Rule containing condition</td><td>rule-deactivated</td></tr><tr><td>Action</td><td>Target</td></tr><tr><td>Element</td><td>NoReplyTimer</td></tr></table>


Table 2.2 Supported conditions, actions and elements in CDIV


Note: In contrast to the CS domain, IMS networks distinguish between Communication Forwarding on Not Logged-in (CFNL) (CDIV using a rule with the condition not-registered) and Forwarding on Not Reachable (CFNRc) (CDIV using a rule with the condition not-reachable). An operator may choose to not apply CFNL and would therefore not include the rule containing the condition not-registered in the XML document. 

If both CFNL and CFNRc are included in the XML document by the operator, then the UE must activate both CFNRc and CFNL to the same target, in order to create compatible user experience with the CS domain. 

In addition to the requirements in section 2.3.2, when configuring settings for the Communication Diversion supplementary service the UE must configure only one of the following in an XCAP request: 

 Communication diversion supplementary service activation, no-reply-timer or both. 

 If the <cp:ruleset> element is present, and a <NoReplyTimer> element is to be created, the UE must include the <cp:ruleset> element in the HTTP PUT request. 

 For the communication diversion services supported in this PRD, elements of one <rule> element for communication diversion supplementary service only. 

Note: It is not possible to create a no-reply timer without including the rule set in a document where a rule set already exists since this would create an invalid XML document according to IETF RFC 4825 [75]. 

If: 

 a <rule> element matching a CDIV service exists in the XML document; and 

 the <target> child element contains empty string; 

then the UE must consider that the CDIV service is not registered for the user otherwise the UE must consider that the CDIV service is registered for the user. 

# 2.3.9 Communication Barring

The UE must support the procedures in 3GPP TS 24.611 [26] with the Release 14 additions to section 4.5.0 and sections 5.3.1.2 and 5.3.1.3 in 3GPP Release 14 TS 24.623 [28]. The 

IMS core network must support the SIP procedures in 3GPP TS 24.611 [26] and can support the procedures in section 5.3.2.5 in 3GPP Release 14 TS 24.623 [28]. For service activation, deactivation, and interrogation (XCAP operations), the UE and the IMS core network must support the XML rules for Barring of All Incoming Calls, Barring of All Outgoing Calls and the conditions listed in Table 2.3. The UE and the IMS core network must support the XML rules as described in section 4.9.1.3 of 3GPP TS 24.611 [26]. 

Note: Support of other conditions is out of scope of the document. 

<table><tr><td>Condition</td></tr><tr><td>Roaming</td></tr><tr><td>International</td></tr><tr><td>International-exHC</td></tr><tr><td>rule-deactivated</td></tr></table>


Table 2.3 Supported conditions in CB


In addition to the requirements in section 2.3.2, when configuring settings for the Communication Barring supplementary service the UE must modify only one of the following in an XCAP request: 

 Incoming communication barring supplementary service activation 

 Outgoing communication barring supplementary service activation 

 For the communication barring services supported in this PRD, elements of one <rule> element for communication barring supplementary service only. 

# 2.3.10 Communication Hold

The UE invoking the HOLD service must not send any media to the other party. 

# 2.3.11 Explicit Communication Transfer - Consultative

The UE must and IMS core network can support the procedures for the consultative transfer defined in 3GPP Release 12 TS 24.629 [87], with the clarifications defined in this sub section. 

The UE as a Transferee must support the procedures with 3rd Party Call Control (3PCC) as defined in 3GPP Release 11 TS 24.628 [71]. The UE procedure without 3PCC is not required. 

The UE and IMS core network must support audio media for the transferred session. 

# 2.3.12 Originating Identification Presentation

The UE and IMS core network must support the SIP procedures in 3GPP Release 13 TS 24.607 [23]. 

The UE must support the presentation of the originating user identity both from the identity within the P-Asserted-Identity header field and the identity within the From header field. 

The UE must support the operator's originating party identity determination policy as defined in clause 4.5.2.12 of Release 14 TS 24.607 [23] also the UE must support being configured according to the "FromPreferred" parameter as specified in Annex C.3. 

Note: As, by default, the identity in the From header field may not be network asserted, it is the responsibility of the network to ensure that the From header field contains a reliable identity of the originating user when it is sent to the UE. 

# 2.4 Call Set-up Considerations

# 2.4.1 SIP Precondition Considerations

Unless preconfigured otherwise by the home operator with the Precondition_disabling_policy parameter as specified in Annex C.3, the UE must use the SIP preconditions framework, as specified in 3GPP Release 13 TS 24.229 [15]. 

If preconditions are used, and the originating UE receives the selected codec in the SDP of a SIP 18x response, then the UE must include only the same codec with its selected configuration parameters in the SDP of the SIP UPDATE request, used for precondition status update. 

The network may disable the use of preconditions in the network; the means by which this takes place is outside the scope of this document. 

The terminating UE implementation must not rely on the use of preconditions by the originating UE. 

Upon receiving an INVITE request, when preconditions are not used by the originating UE or preconditions are disabled by the network, and the local resources required at the terminating UE are not available, the terminating UE, according to 3GPP Release 13 TS 24.229 [15], must: 

send a SIP 183 (Session Progress) response containing SDP. If the received INVITE request includes a Supported header field with the value "100rel", this 183 (Session Progress) response must be sent reliably; 

 not use the precondition mechanism; 

 not alert the user until resources are reserved successfully on the terminating side; and 

not send a SIP 180 (Ringing) response until resources are reserved successfully on the terminating side. 

# 2.4.2 Integration of resource management and SIP

# 2.4.2.1 Loss of PDN connectivity

If the Packet Data Network (PDN) connectivity between a UE and the network is lost, the network must terminate all ongoing SIP sessions related to this UE, according to the procedures in section 5.2.8 of 3GPP TS 24.229 [15] (e.g. when the P-CSCF receives an abort session request from the Policy and Charging Rules Function (PCRF)). 

If the UE discovers (for example during a TAU procedure) that PDN connectivity had been lost, then the UE must attempt to re-establish the PDN connection. This will trigger the network to initiate a new SIP signalling bearer in conjunction with the PDN connection establishment. 

Note: The PDN connectivity may also be lost if the UE moves to GERAN/UTRAN, see also GSMA PRD IR.88 [67]. It may not be possible to re-establish the PDN connectivity in GERAN/UTRAN in such deployments. 

When the UE regains PDN and IP connectivity, if the IP address has changed or the IMS registration expired during the period of absence of IP connectivity then the UE must perform a new initial registration to IMS. 

# 2.4.2.2 Void

# 2.4.2.3 Loss of media bearer and Radio Connection

If a Guaranteed Bit Rate (GBR) bearer used for voice fails to get established, or is lost midsession, then the network must terminate the session associated to the voice stream according to the procedures in section 5.2.8 of 3GPP TS 24.229 [15] (P-CSCF must be informed about loss of bearer by the PCRF). 

Note 1: The loss of the GBR bearer may be due to loss of radio connection indicated by an S1 release with cause "Radio Connection With UE Lost" and then followed by the MME Initiated Dedicated Bearer Deactivation procedure for the GBR bearer used for voice. Or, the GBR bearer may be lost or not established, due to the current resource and radio situation. However, termination of the SIP session due to loss of the voice GBR bearer is the only way for the system to stop the IMS level charging (quickly) when the UE loses radio connection. 

Note 2: If other media types are used, and a GBR bearer used for another media type fails to get established, or is lost mid-session, then the network, based on its policies, has the option to either allow the SIP session to continue as is, or terminate the SIP session that the GBR bearer is associated with (the network can handle loss of video in a video call in such a way that the session continues as voice-only). 

If a SIP session includes media streams, and if a dedicated bearer for any media stream fails to get established, or is lost mid-session, then the UE must, based on its preferences, modify, reject or terminate the SIP session that the dedicated media bearer is associated with, according to section 6.1.1 of 3GPP TS 24.229 [15]. The UE can act differently per media type. 

Note 3: If a voice bearer is lost or fails to get established, the network will, in normal cases, release the session as described in the beginning of this section. As a complement to this, the UE must have internal logic to react to the detection of loss of bearer/radio connection to handle its internal state. For a multimedia communication, if the radio connection is not lost, but a bearer not used for voice is lost, then the UE must decide if the session should be maintained as is, should be modified, or should be released. 

If the UE loses radio connectivity and the IMS registration expires prior to regaining radio connectivity, then upon regaining radio connectivity the UE must perform a new initial registration to IMS. 

# 2.4.3 Voice Media Considerations

# 2.4.3.1 General

The SDP offer/answer for voice media must be formatted as specified in section 6.2.2 of 3GPP Release 12 TS 26.114 [35], with the restrictions included in the present document. If the Enhanced Voice Services (EVS) codec is included, then the offer/answer for voice media must be formatted as specified in section 6.2.2 of 3GPP Release 12 TS 26.114 [35], with the restrictions included in the present document. 

If multiple audio bandwidths are offered by the UE for speech communication, then the codec preference order must be as specified in clauses 5.2.1.5 and 5.2.1.6 of 3GPP Release 12 TS 26.114 [35]. 

Unless preconfigured otherwise by the home operator with the 

Default_EPS_bearer_context_usage_restriction_policy parameter as specified in Annex C.3, if a dedicated bearer for the media does not exist, the UE must consider itself not having local resources. If the UE has no local resources, the UE must not send media. See also section L.2.2.5.1B in 3GPP TS 24.229 [15]. 

Note 1: The existence of a dedicated bearer does not grant by itself the UE authority to send media. Other conditions need to be fulfilled. 

Note 2: The originating and terminating networks can modify the SDP offer for voice media. 

# 2.4.3.2 AMR and AMR-WB

The UE must include in an initial SDP offer at least: 

 one AMR-WB payload type with no mode-set specified, and 

 one AMR payload type with no mode-set specified, 

both as defined in table 6.1 of 3GPP Release 12 TS 26.114 [35]. 

The UE must set the b=AS to match the highest codec mode for the offer (maximum codec bit rate if no mode set is included). 

The UE, upon receiving an initial SDP offer containing a payload description for AMR with no mode-set included, and accepting the payload description with no mode-set, must include into the SDP answer the value assigned to the RateSet parameter for AMR as specified in Annex C.3. It is recommended to set the RateSet parameter for AMR to the value 0,2,4,7 (i.e. mode set=0,2,4,7 included in the SDP answer). 

The UE, upon receiving an initial SDP offer containing a payload description for AMR-WB with no mode-set included, and accepting the payload description with no mode-set, must include into the SDP answer the value assigned to the RateSet parameter for AMR-WB as specified in Annex C.3. It is recommended to set the RateSet parameter for AMR-WB to "undefined" (i.e. no mode-set included). A UE that intends to use AMR-WB 12.65 as highest mode must have the RateSet parameter set to $" 0 , 1 , 2 "$ and include mode-set=0,1,2 in the SDP answer. 

The SDP answer for AMR with no mode-set included must be interpreted by the UE that all eight AMR modes can be used. 

The SDP answer for AMR-WB with no mode-set included must be interpreted by the UE that all nine AMR-WB modes can be used. 

The UE must set the $\mathsf { b } { = } \mathsf { A } \mathsf { S }$ to match the highest codec mode for the answer (maximum codec bit rate if no mode set is included). 

# 2.4.3.3 EVS

If the EVS codec is offered for super-wideband calls by a UE, then the UE that sends the SDP offer for voice media must include in this SDP offer at least one EVS payload type with one of the following EVS configurations: 

 EVS Configuration A1: br=5.9-13.2; bw $\underline { { \underline { { \mathbf { \Pi } } } } } =$ nb-swb. 

 EVS Configuration A2: br=5.9-24.4; bw=nb-swb. 

 EVS Configuration B0: b $\mathbf { \tilde { = } }$ 13.2; bw=swb. 

 EVS Configuration B1: br=9.6-13.2; bw $\underline { { \underline { { \mathbf { \Pi } } } } } =$ swb. 

 EVS Configuration B2: br=9.6-24.4; bw=swb. 

The UE may also include in this SDP offer ch-aw-recv=x with x set to a value out of the set $\{ -$ 1,0,2,3,5,7}. The UE must support being configured according to the "ICM/INIT_PARTIAL_REDUNDANCY_OFFSET_RECV" parameter as specified in Annex C.3. If "ICM/INIT_PARTIAL_REDUNDANCY_OFFSET_RECV" parameter is undefined, then the UE must not include ch-aw-recv into the SDP offer. SDP parameters other than br, bw, max-red and ch-aw-recv must not be included in a media format description associated with the EVS codec within the initial SDP offer (for a list of SDP parameters see Table 6.2a in 3GPP Release 12 TS 26.114 [35]). 

Note 1: If ch-aw-recv is not included in the SDP, this is identical to include ch-awrecv=0, as specified in 3GPP Release 12 TS 26.445 [79]. 

The configuration of the EVS payload type to be included first in the initial SDP offer for EVS is defined by the EVS/Br and EVS/Bw parameters as specified in Annex C.3, which must be configured to one of the five above EVS Configurations. 

If the EVS codec is offered for super-wideband calls by a UE, then the UE that sends the initial SDP offer should also include in this initial SDP offer one EVS payload type with audio bandwidth range up to super-wideband and with no restrictions on bitrate range and no restriction on mode-set. If this EVS payload type is not included then: 

an initial SDP offer with EVS configuration B0 or B1 listed first must also include a second payload type with EVS configuration A1; and 

an initial SDP offer with EVS configuration B2 listed first must also include a second payload type with EVS configuration A2. 

The UE must support all SDP parameters applicable to EVS that can be received in a SDP offer as specified in 3GPP Release 12 TS 26.114 [35] and 3GPP Release 12 TS 26.445 [79]. 

A payload type in the received SDP offer is considered to match the EVS configuration "X" if the values the payload type indicates for the "br" and "bw" parameters are exactly as specified above for configuration "X". The inclusion of additional parameters and the values 

to which those parameters are set has no bearing on whether this inclusion matches the standard configuration "X". 

A UE that supports super-wideband calls upon receiving and accepting a payload type in the received SDP offer for EVS for an incoming call, compliant with the offer described above, must answer according to both the received SDP Offer and the UE's EVS configuration (i.e. EVS/Br and EVS/Bw parameters as specified in see Annex C.3) as described in table 2.4 below: 

<table><tr><td></td><td colspan="5">EVS configuration of the UE that received the SDP Offer</td></tr><tr><td>Received SDP Offer for EVS (preferred payload type listed first)</td><td>A1</td><td>A2</td><td>B0</td><td>B1</td><td>B2</td></tr><tr><td>A1</td><td>A1</td><td>A1</td><td>A1</td><td>A1</td><td>A1</td></tr><tr><td>A2</td><td>A1</td><td>A2</td><td>A1</td><td>A1</td><td>A2</td></tr><tr><td>B0</td><td>B0</td><td>B0</td><td>B0</td><td>B0</td><td>B0</td></tr><tr><td>B1</td><td>A1</td><td>A1</td><td>B1</td><td>B1</td><td>B1</td></tr><tr><td>B2</td><td>A1</td><td>A2</td><td>B1</td><td>B1</td><td>B2</td></tr></table>


Table 2.4 SDP content to be included in an SDP answer for a superwideband call



Note 2: This table applies only to received SDP Offers compliant with this specification, i.e. including A1, if B0 or B1 are listed first and including A2, if B2 is listed first.


If the selected EVS configuration is A1, B0 or B1 then "mode s $\mathsf { e t } = 0 , 1 , 2 ^ { \scriptscriptstyle " }$ must be included in the SDP answer. 

The UE must add only SDP parameters that are applicable to EVS in the SDP answer that are already present in the corresponding received and accepted SDP Offer. If SDP parameters applicable to EVS are included in the accepted SDP offer, then the UE must handle these parameters as specified in 3GPP Release 12 TS 26.445 [35]. 

If the SDP parameter ch-aw-recv is present in the corresponding received and accepted SDP offer, then the SDP parameter ch-aw-recv must be included in the SDP answer with the same value as received. 

Default values as specified in 3GPP Release 12 TS 26.445 [35] apply for all other SDP parameters applicable to EVS that are not included in the SDP Answer. 

# 2.4.4 Multimedia Considerations

UEs using the full set of media functions can send SDP offers containing multiple $" \mathsf { m } = "$ lines to indicate the wish to establish a more advanced multimedia session than this profile defines. 

If one of these $" \mathsf { m } = "$ lines indicates the wish of establishing an audio (voice) session (using a compatible codec), then the UE following this profile must accept the offer and allow the use of whatever media streams it supports. The UE must set the port number to 0 (zero) for the media streams it does not support. 

Note 1: This means that a voice-only UE will accept a video call request, but the call will automatically be transformed to a voice-only call. In CS telephony, the call is rejected when the terminating client cannot support all offered media (that is a voice-only terminal will reject a video call offer). Hence, this section describes a behaviour that is new to telephony. 

UEs using the full set of media functions, have the option to try to update the session by sending SIP (re-)INVITE requests that include SDP offers containing multiple $" \mathsf { m } = "$ lines, to indicate the desire to expand the session into a more advanced multimedia session. The UE following this profile must accept such an offer and allow the use of whatever media streams the UE supports. The UE must, in the SDP answer, set the port number to 0 (zero) for the media streams it does not support. 

Note 2: This means that a voice-only capable UE will accept a request to update the session to video using a SIP 200 (OK) response. But since the SDP answer will disable the video stream, the call will continue as a voice-only call. 

# 2.4.5 Call Composer Service

The UE must and the network can support the Call Composer service. 

The Call Composer service is enabled if the value of the configuration parameter COMPOSER AUTH (see Annex C.3) is set to "2" or "3". 

The UE must allow the user to set Call Composer elements in a SIP INVITE request if the peer UE also supports the Call Composer Service. The support of Call Composer at the peer UE can be determined via: 

use of Capability Discovery, if supported and enabled as described in section 5.7, otherwise 

if the last INVITE request or response or SIP OPTIONS request or response from the Public User Identify contained the Call Composer media feature tag in the Contact header an incoming INVITE request. 

# 2.5 SMS over IP

The UE must implement the roles of an SM-over-IP sender and an SM-over-IP receiver, according to sections 5.3.1 and 5.3.2 of 3GPP TS 24.341 [19]. 

The status report capabilities, delivery reports, and notification of having memory available, according to sections 5.3.1.3, 5.3.2.4 and 5.3.2.5 of 3GPP TS 24.341 [19] must be supported by the UE and the IMS core network. 

The IMS core network must take the role of an IP-SM-GW and support the general procedures in section 5.3.3.1 of 3GPP TS 24.341 [19], and the following functions: 

answering of routing information query and obtaining the routing information according to the procedures in section 5.3.3.3 in 3GPP TS 24.341 [19]; and 

 transport layer interworking according to sections 5.3.3.4 of 3GPP TS 24.341 [19]. 

# 2.6 User Agent and Server Headers

The UE must include the User-Agent header in all SIP requests and the Server header in all SIP responses. The UE must include the User-Agent header in HTTP requests for XCAP. The headers must be compiled as defined in GSMA PRD RCC.07 [103] section C.4.1 including the following amendment: 

product-list $=$ /enabler \* (LWS enabler) [LWSterminal][LWSdevice-type][LWSmno-customisation]\* (LWS list-extension) 

The rule "enabler" is defined in GSMA GSMA PRD RCC.07 [103] section C.4.1 and is extended as follows: 

enabler $= /$ GSMA-PRD   
GSMA-PRD $\equiv$ "PRD-" PRD-code SLASH major-version-number   
PRD-code $=$ "IR92" / token   
major-version-number $= 1^{\star}$ DIGIT; the major version number of the GSMA PRD   
document version 

The rule "terminal" is defined in RCC.07 [103] section C.4.1. 

The rules "mno-customization" and "device-type" are defined as an extension to RCC.07 [103] section C.4.1 as follows: 

list-extension $=$ / device-type / mno-customisation   
device-type $\equiv$ "device-type" SLASH device-classification   
device-classification $\equiv$ token; token taken from the ; device classification registry defined in IETF RFC 7852 [104]   
mno-customisation $\equiv$ "mno-custom" SLASH customisation   
customisation $\equiv$ open-market / customised   
open-market $\equiv$ "none"   
customised $\equiv$ MCC-MNC / free-text   
MCC-MNC $\equiv$ MCC MNC $\mathrm{MCC} = 3\mathrm{DIGIT}$ ;the E.212 Mobile Country code assigned to the operator ; country   
MNC $\equiv$ 3DIGIT; the E.212 Mobile Network Code assigned to the ; operator, a two digit MNC is padded out to 3 digits . by inserting a O at the beginning free-text $\equiv$ token; a human readable string to identify the ; customisation 

Examples of User-Agent header constructed according to the rules above: 

```txt
User-Agent: PRD-IR92/11 term-Vendor1/Model1-XXXX device-type/features-phonemno-custom/none  
User-Agent: PRD-IR92/12 term-Vendor2/Model2-YYYY device-type/smart-phonemno-custom/235015 
```

User-Agent: PRD-IR92/13 term-Vendor3/Model3-zzzz device-type/smart-phone mno-custom/ex.telekom 

Note 1: The User-Agent and Server headers are meant to assist persons in analyzing the network behavior. It is not intended that their presence, content or syntax, influence the network behavior. 

Note 2: Within a trust domain, network(s) are expected not to add, remove or modify User-Agent and Server headers. This applies whether a given network element functions as a SIP proxy or Back to Back User Agent (B2BUA). 

# 3 IMS Media

# 3.1 General

This section endorses a set of media capabilities specified in 3GPP TS 26.114 [35]. The section describes the needed SDP support in UEs and in the IMS core network and it describes the necessary media capabilities both for UEs and for entities in the IMS core network that terminate the user plane. Examples of entities in the IMS core network that terminate the user plane are the Media Resource Function Processor (MRFP) and the Media Gateway (MGW). 

# 3.2 Voice Media

# 3.2.1 Codecs

The UE must support the Adaptive Multi-Rate (AMR) speech codec, as described in 3GPP TS 26.071 [29], 3GPP TS 26.090 [31], 3GPP TS 26.073 [30], and 3GPP TS 26.104 [34], including all eight (8) modes and source rate controlled operations, as described in 3GPP TS 26.093 [32]. The UE must be capable of operating with any subset of these eight (8) codec modes. 

The UE must support the AMR wideband (AMR-WB) speech codec as described in 3GPP TS 26.114 [35], 3GPP TS 26.171 [38], 3GPP TS 26.190 [40], 3GPP TS 26.173 [39] and 3GPP TS 26.204 [42], including all nine (9) modes and source controlled rate operation 3GPP TS 26.193 [41]. The UE must be capable of operating with any subset of these nine (9) codec modes. If the EVS codec is supported, then the EVS AMR-WB IO mode of operation may be used as an alternative implementation of AMR-WB as specified in clause 5.2.1.4 of 3GPP Release 12 TS 26.114 [35]. 

If super-wideband or fullband speech communication is offered, then the UE must support and offer the EVS codec as described in 3GPP Release 12 TS 26.114 [35], 3GPP Release 12 TS 26.441 [76], 3GPP Release 12 TS 26.442 [77], 3GPP Release 12 TS 26.443 [78], 3GPP Release 12 TS 26.445 [79], 3GPP Release 12 TS 26.446 [80], 3GPP Release 12 TS 26.447 [81], 3GPP Release 12 TS 26.449 [82], 3GPP Release 12 TS 26.450 [83] and 3GPP Release 12 TS 26.451 [84]. 

The UE must support handling of CMR within RTP payload as specified in clause 7.5.2.1.2.2 of 3GPP Release 13 TS 26.114 [35]. 

When transmitting using the AMR codec, the AMR-WB codec or the EVS codec in the AMR-WB IO mode mode of operation, then the UE must be capable of aligning codec mode changes to every frame border, and must also be capable of restricting codec mode changes to be aligned to every other frame border e.g. as described for UMTS_AMR_2 in 

3GPP TS 26.103 [33] based on the SDP offer-answer negotiation. The UE must also be capable of restricting codec mode changes to neighbouring codec modes within the negotiated codec mode set based on the SDP offer-answer negotiation. 

When receiving using the AMR codec, the AMR-WB codec or the EVS codec in the AMR-WB IO mode mode of operation, then the UE and the entities in the IMS core network that terminate the user plane must allow codec mode changes at any frame border and to any codec mode within the negotiated codec mode set. As an exception, entities in the network that provide Circuit Switched (CS) interworking and apply Transcoder-Free Operation (TrFO) of Tandem-Free Operation (TFO) must accept codec mode changes in accordance with the capabilities at the CS network side. 

Entities in the IMS core network that terminate the user plane supporting speech communication and supporting TFO and/or TrFO must support: 

AMR speech codec modes 12.2, 7.4, 5.9 and 4.75 as described in 3GPP TS 26.071 [29], 3GPP TS 26.090 [31], 3GPP TS 26.073 [30], and 3GPP TS 26.104 [34]. 

Entities in the IMS core network that terminate the user plane supporting super-wideband speech communication must support: 

EVS speech codec as described in 3GPP Release 12 TS 26.441 [76], 3GPP Release 12 TS 26.442 [77], 3GPP Release 12 TS 26.443 [78], 3GPP Release 12 TS 26.445 [79], 3GPP Release 12 TS 26.447 [81], 3GPP Release 12 TS 26.449 [82], 3GPP Release 12 TS 26.450 [83] and 3GPP Release 12 TS 26.451 [84]. 

Entities in the IMS core network that terminate the user plane supporting wideband speech communication and supporting TFO and/or TrFO must support: 

AMR-WB speech codec modes 12.65, 8.85 and 6.60 as described in 3GPP TS 26.171 [38], 3GPP TS 26.190 [40], 3GPP TS 26.173 [39], and 3GPP TS 26.204 [42]. 

Entities in the IMS network that provide transcoding-free interworking to the CS network must be capable of requesting the UE to restrict codec mode changes to be aligned to every other frame border and also be capable of requesting the UE to restrict codec mode changes to neighbouring codec modes within the negotiated codec mode set. 

Note: Restrictions in codec mode changes are required only for transcoder-free interworking with a CS GSM MS (Mobile Station). 

# 3.2.2 RTP Profile and SDP Considerations

# 3.2.2.1 RTP Profile

The Real Time Protocol (RTP) profile, Audio Video Profile (AVP) IETF RFC 3551 [57] must be used by the UE and the IMS core network. 

# 3.2.2.2 SDP Offer Considerations

The SDP Capability Negotiation framework described in IETF RFC 5939 [64] must not be used in the SDP offer by the UE and the IMS core network when the AVP profile is used. 

# 3.2.2.3 SDP Answer Considerations

The UE and the IMS core network must be able to receive and answer to an SDP offer that uses SDPCapNeg. The answer must indicate the use of the RTP AVP profile. 

Note: In section 6.2.1a of 3GPP TS 26.114 [35], it is recommended that that a UE or the IMS core network use the SDPCapNeg attributes "tcap"’ and "pcfg" to indicate the support of both the RTP profiles AVP and AVP Feedback Profile (AVPF). Hence, to be forward compatible with equipment using the full set of media functions, a minimum set UE and the IMS core network must be able to ignore the SDPCapNeg attributes and answer to the RTP AVP profile in the offer. 

# 3.2.2.4 SDP Bandwidth Negotiation

The UE and network must use the $\mathtt { b } { = } { \mathsf { A } } { \mathsf { S } }$ parameter in SDP offers and answers for bandwidth negotiation as defined in section 6.2.5.2 of 3GPP Release 10 TS 26.114 [35] for UEs and networks that support AMR and AMR-WB, and 3GPP Release 12 TS 26.114 [35] for UEs and networks that support EVS. 

# 3.2.3 Data Transport

The UE and the entities in the IMS core network that terminate the user plane must use RTP over UDP as described in IETF RFC 3550 [56] and IETF RFC 768 [53], respectively, to transport voice and use symmetric RTP as defined in IETF RFC 4961 [72]. 

# 3.2.4 RTCP Usage

The RTP implementation must include an RTP Control Protocol (RTCP) implementation according to IETF RFC 3550 [56]. 

The UE and the entities in the IMS core network that terminates the user plane must use symmetric RTCP as defined in IETF RFC 4961 [72]. 

The bandwidth for RTCP traffic must be described using the "RS" and "RR" SDP bandwidth modifiers at media level, as specified by IETF RFC 3556 [58]. Therefore, a UE must include the $\ " b = \mathsf { R S }$ :" and "b=RR:" fields in SDP, and a UE and the entities in the IMS core network that terminate the user plane must be able to interpret them. If the $\ " b = \mathsf { R S }$ :" field or "b=RR:" field or both these fields are not included in a received SDP (offer or answer), then the UE must use the recommended default value for the missing field(s) as defined in IETF RFC 3556 [58]. 

The UE and the entities in the IMS core network that terminate the user plane must send RTCP packets when media (including early media) is sent or received. Once an RTCP packet is sent according to received SDP of a SIP dialog, RTCP packets must be sent by UEs and entities in the IMS core network that terminate the user plane according to the received SDP of the SIP dialog for the remaining duration of the SIP dialog. For unidirectional media (e.g. early media or during call hold), RTCP packets must always be sent by both UEs and entities in the IMS core network that terminate the user plane. If multiple early dialogs are created due to forking (see section 2.2.5), the UE must send the RTCP packets according to received SDP answers of those early dialogs for which the IP address and port received in the SDP match the IP address and port of received media. 

Note 1: The RTCP is based on the periodic transmission of control packets to all participants in the session, as described in IETF RFC 3550 [56]. In the context of this document, the primary uses of RTCP are voice quality monitoring, and to provide link aliveness information while the media are on hold. The latter implies that the RTCP transmission must continue when the media are on hold. 

The UE and the entities in the IMS core network that terminates the user plane must set the sending frequency of control packets to a value calculated from the values of "RS" and "RR" SDP bandwidth modifiers according to rules and procedures in IETF RFC 3550 [56]. The UE must set the "RS" and "RR" SDP bandwidth modifiers such that RTCP packets are sent to the UE at least once every 5 seconds, in order to allow a sufficiently tight inactivity detection. 

The UE and the entities in the IMS core network that terminate the user plane must support the transmission of RTCP packets formatted according to the rules in IETF RFC 3550 [56] and with the following clarifications below. 

The UE and the entities in the IMS core network that terminate the user plane must use the RTCP compound packet format. When sent, the compound packet must include one report packet and one Source Description (SDES) packet. When no RTP packets have been sent in the last two reporting intervals, the UE and the entities in the IMS core network that terminate the user plane should send a Receiver Report (RR). Receiving of a Sender Report (SR) instead of an RR must be handled and accepted as valid by the UE and the entities in the IMS core network that terminate the user plane. 

The SR, RR and SDES packets must be formatted as described below: 

For SR and RR RTCP packets: 

 Version 2 must be used; and 

 Padding must not be used (and therefore padding bit must not be set). 

For SDES RTCP packets: 

 version and Padding as described for SR packet must be used; 

 the SDES item CNAME must be included in one packet; and 

 other SDES items should not be used. 

Note 2: Because the randomly allocated SSRC identifier may change, the CNAME item must be included to provide the binding from the SSRC identifier to an identifier for the source that remains constant. Like the SSRC identifier, the CNAME identifier must be unique among all other participants within one RTP session. 

To be forward compatible and interwork with legacy equipment, the UE and the entities in the IMS core network that terminate the user plane must be able to receive all types of RTCP packets, according to the rules specified in IETF RFC 3550 [56]. 

RTCP is controlled on a per session basis by the SDP offer/answer exchange as defined in 3GPP TS 26.114 [35] with the following clarifications: 

If the UE receives an SDP offer that contains $\ " { \sf b } = { \sf R } { \sf S } "$ attribute set to zero, then the UE must set the $\ " { \sf b } = { \sf R } { \sf S } "$ attribute to zero in an SDP answer to that SDP offer. If the UE receives an SDP offer that contains $\ " \mathrm { b } = \mathsf { R } \mathsf { R } ^ { \prime \prime }$ attribute set to zero, then the UE must set the "b=RR" attribute to zero in an SDP answer to that SDP offer. If the UE receives an SDP offer that contains both "b=RR" and $\ " { \sf b } = { \sf R } { \sf S } "$ attributes set to zero, then the UE must not send RTCP packets and must consider RTCP to be disabled for the session. 

If the UE received an SDP answer containing zero values in both of the $\ " { \sf b } = { \sf R } { \sf S } "$ and "b=RR" attributes, then (regardless of the values assigned to these attributes in the corresponding SDP offer) the UE must not send RTCP packets and must consider RTCP to be disabled for the session. 

The UE must accept receiving RTCP packets for a session that the UE considers RTCP to be disabled. The UE is not required to process these received RTCP packets. 

# 3.2.5 Speech Payload Format Considerations

The Adaptive Multi Rate (AMR) and Adaptive Multi-Rate Wideband (AMR-WB) payload format(s) specified in IETF RFC 4867 [63] must be supported by the UE and the entities in the IMS core network that terminate the user plane. If the EVS codec is supported, then the EVS payload format specified in 3GPP Release 12 TS 26.445 [79] must be supported. 

The UE and the entities in the IMS core network that terminates the user plane must support the bandwidth-efficient and the octet-aligned formats of the AMR and AMR-WB payload formats. The UE and the entities in the IMS core network that terminates the user plane must request the use of bandwidth-efficient format of the AMR and AMR-WB payload format when originating a session. 

The UE and the entities in the IMS core network that terminates the user plane must send the number of speech frames, or fewer, encapsulated in each RTP packet, as requested by the other end using the ptime SDP attribute. 

The UE and the entities in the IMS core network that terminates the user plane must request to receive one speech frame encapsulated in each RTP packet, but must accept any number of frames per RTP packet, up to the maximum limit of 12 speech frames per RTP packet. 

Note 1: This means that the ptime attribute must be set to 20 and the maxptime attribute must be set to 240 in the SDP negotiation. 

An IMS MGW not supporting redundancy may limit the maxptime attribute to 80 in the SDP negotiation. 

The UE and the entities in the IMS core network that terminates the user plane must be able to sort out the received frames based on the RTP Timestamp and must remove duplicated frames, if present. If multiple versions of a frame are received, e.g. encoded with different bit rates, then the frame encoded with the highest bit rate should be used for decoding. 

Note 2: UEs and the entities in the IMS core network that terminate the user plane, using the full set of media functions, have the option to send frames several times (for redundancy) to adapt for conditions with high packet-loss ratios. It is thus important that a UE and the entities in the IMS core network that 

terminate the user plane that use this profile are capable to detect and drop the duplicated frames. 

RTCP-APP must not be used for Codec Mode Requests (CMR) by the UE and the entities in the IMS core network that terminate the user plane. 

Note 3: As the speech media uses the RTP AVP profile as specified in section 3.2.2.1, the adaptation using RTCP may be too slow and therefore unsuitable. 

# 3.2.6 Jitter Buffer Management Considerations

The minimum performance requirements for jitter buffer management of voice media, as described in 3GPP TS 26.114 [35] must be met. If the EVS codec is supported, then the jitter buffer management requirements in section 8.2 of 3GPP Release 12 TS 26.114 [35] must be met. 

# 3.2.7 Front End Handling

UEs used for IMS voice services must conform to the minimum performance requirements on the acoustic characteristics of 3G terminals specified in 3GPP TS 26.131 [36]. The codec modes and source control rate operation (DTX) settings must be as specified in 3GPP TS 26.132 [37]. 

# 3.3 DTMF Events

The UE and the IMS core network must support DTMF events as defined in Annex G of 3GPP TS 26.114 [35]. 

If the UE receives an SDP offer with no telephone-event codec included, then the UE must not reject the SDP offer for this reason and the UE must not send DTMF events using the telephone-event codec for the negotiated session. 

Note: Transport of DTMF events from the UE using the telephone-event codec during a session is impossible unless the telephone-event payload type has been negotiated. 

# 4 Radio and Packet Core Feature Set

# 4.0 General

The LTE radio capabilities included in this specification are applicable to UEs and networks supporting FDD LTE only, TDD LTE only, or both FDD LTE and TDD LTE. 

# 4.1 Robust Header Compression

The UE and the network must support Robust Header Compression (RoHC) as specified in 3GPP TS 36.323 [51], IETF RFC 3095 [54] and IETF RFC 4815 [62]. The UE and network must be able to apply the compression to packets that are carried over the radio bearer dedicated for the voice media. At minimum, the UE and network must support "RTP/UDP/IP" profile (0x0001) to compress RTP packets and "UDP/IP" profile (0x0002) to compress RTCP packets. The UE and network must support these profiles for both IPv4 and IPv6. 

# 4.2 LTE Radio Capabilities

# 4.2.1 Radio Bearers

The UE must support the following combination of radio bearers (see Annex B in 3GPP TS 36.331 [52]): 

 SRB1 + SRB2 + 4 x AM DRB + 1 x UM DRB 

The network must support the following combination of radio bearers: 

 SRB1 + SRB2 + 2 x AM DRB + 1 x UM DRB 

One AM Data Radio Bearer (DRB) is utilized for an Evolved Packet System (EPS) bearer with Quality of Service Class Indicator $( \mathsf { Q C l } ) = 5$ and another AM DRB for EPS bearer with $\mathsf { Q C l } = 8 / 9$ . UM DRB is utilized for EPS bearer with $\mathsf { Q C l } = 1$ . EPS bearer usage is described in section 4.3. 

# 4.2.2 DRX Mode of Operation

In order to maximize lifetime of the UE battery, the UE and the network must support LTE Discontinuous Reception (DRX) method as specified in 3GPP TS 36.300 [49] and 3GPP TS 36.321 [50] must be deployed. 

# 4.2.3 RLC configurations

Radio Link Control (RLC) entities must be configured to perform data transfer in the following modes as specified in 3GPP TS 36.322 [69]: 

 Unacknowledged Mode (UM) for EPS bearers with $\mathsf { Q C l } = 1$ 

 Acknowledged Mode (AM) for EPS bearers with $\mathsf { Q C l } = 5$ 

 Acknowledged Mode (AM) for EPS bearers with $\mathsf { Q C l } = 8 / 9$ 

Voice service can tolerate error rates on the order of $1 \%$ , while benefiting from reduced delays, and is mapped to a radio bearer running the RLC protocol in unacknowledged mode (UM). 

EPS bearer usage is described in section 4.3. 

# 4.2.4 GBR and NGBR Services, GBR Monitoring Function

Voice is one of the LTE services that require a GBR bearer as described in 3GPP TS 23.401 [10]. The GBR bearer for voice is realised via dedicated network resources that are allocated by an admission control function in the eNodeB at bearer establishment. Reports from the UE, including buffer status and measurements of UE’s radio environment, are required to enable the scheduling of the GBR bearer as described in 3GPP TS 36.300 [49]. In UL it is the UE’s responsibility to comply with GBR requirements. 

The non-GBR bearer (NGBR) does not support a guaranteed bit rate over the radio link and is thus not suitable for IMS-based voice services. 

# 4.2.5 E-UTRA NR Dual connectivity

The UE may support and the network can support E-UTRA NR Dual Connectivity (EN-DC) as defined in 3GPP Release 15 TS 37.340 [101]. The UE may support EN-DC as specified in 3GPP Release 15 of TS 36.331 [52] and TS 38.331 [102]. 

# 4.3 Bearer Management

# 4.3.1 EPS Bearer Considerations for SIP Signalling, HTTP for XCAP and HTTP Content Server

For SIP signalling, the IMS application in the UE must use the IMS well-known APN as defined in GSMA PRD IR.88 [67]; the UE must prevent non-IMS applications from using the IMS well-known APN. 

Unless preconfigured by the home operator with the EPS_initial_attach_ConRefs parameter as specified in Annex C.3 to provide the IMS well-known APN during initial attach, the UE must not provide the IMS well-known APN during the E-UTRAN initial attach procedure. 

Note 1: The network has to be prepared to receive any APN, including the IMS wellknown APN, during the E-UTRAN initial attach procedure, as per 3GPP TS 23.401 [10] and 3GPP TS 24.301 [17]. 

Note 2: When preconfiguring the UE to provide the IMS well-known APN during initial attach, the home operator needs to ensure that the IMS well-known APN is part of the subscription of the user of the UE in order to avoid attach failure. How the home operator preconfigures the UE is out of the scope of this PRD. 

If procedures in section 2.2.1 require the UE to register with IMS, and the PDN connection to the IMS well-known APN does not exist yet (e.g. when the PDN connection established during the initial attach is to an APN other than the IMS well-known APN) then the UE must establish a PDN connection to the IMS well-known APN. 

Note 3: PDN Connection establishment can be caused by a SIP registration request. Sending a SIP registration request per the note in section 2.2.1 can cause PDN Connection establishment even if the IMS voice over PS Session indicator indicates that IMS voice over PS session is not supported. 

Note 4: For all cases when the UE provides the IMS well-known APN, the APN Operator Identifier is not included by the UE. 

A default bearer must be created by the network when the UE creates the PDN connection to the IMS well-known APN, as defined in 3GPP specifications. A standardised QCI value of five (5) must be used for the default bearer. The default bearer is used for IMS SIP signalling. 

A default bearer must be created by the network when the UE creates the PDN connection for emergency bearer services, as defined in 3GPP specifications. A standardised QCI value of five (5) and an ARP value that is reserved for emergency services must be used for the default bearer. The default bearer is used for IMS SIP signalling. 

The UE must and the network can support Back-off timer value IE in PDN Connectivity Reject and the UE must start the ESM back-off timer according to the value indicated by the Back-off timer value IE as specified in 3GPP Release 12 TS 24.301 [17]. If the Back-off timer value IE is not included in a PDN Connectivity Reject, and the PDN Connectivity Reject is for a standalone PDN CONNECTIVITY REQUEST, then the UE must apply a default value of 12 minutes for the ESM back-off timer for the cause values #8 "operator determined barring", #27 "missing or unknown APN", #32 "service option not supported", and #33 "requested service option not subscribed" as described in section 6.5.1.4.3 of 3GPP Release 12 TS 24.301 [17]. 

For XCAP and HTTP Content Server requests, the UE must be preconfigured or provisioned by the home operator with the ToConRef parameter as specified in Annex C.3 with the Network Identifier part of the APN for Home Operator Services to be used for these requests (see GSMA PRD IR.88 [67] for more information). 

Note 5: How the home operator preconfigures or provisions the UE with the Network Identifier part of the APN for Home Operator Services is out of the scope of this PRD. 

For XCAP and HTTP Content Server requests, the UE must establish the PDN connection to the APN for HOS only when required (unless already established), e.g. when the user modifies a supplementary service’s setting. In case the UE did not re-use an established PDN connection (e.g. in case the HOS APN is the internet APN), the UE must close the connection at most 120s after the last transaction has been completed. 

# 4.3.2 EPS Bearer Considerations for Voice

For an IMS session request for a Conversational Voice call (originating and terminating), a dedicated bearer for IMS-based voice must be created by the network utilising interaction with dynamic PCC. The network must initiate the creation of a dedicated bearer to transport the voice media. The dedicated bearer for Conversational Voice must utilise the standardised QCI value of one (1) and have the associated characteristics as specified in 3GPP TS 23.203 [4]. Since the minimum requirement for the UE is the support of one (1) UM bearer that is used for voice (see section 7.3.1 and Annex B of 3GPP TS 36.331 [52]), the network must not create more than one dedicated bearer for voice media. Therefore, the UE and network must be able to multiplex the media streams from multiple concurrent voice sessions. 

Note 1: A single bearer is used to multiplex the media streams from multiple concurrent voice sessions; this is necessary in some supplementary services (e.g. CW, CONF). 

Note 2: The sharing of a single GBR bearer for voice means that different QCI and/or ARP values are not possible for different voice streams. 

When the UE has an ongoing conversational voice call, the UE must follow the procedures for access domain selection related to "Persistent EPS bearer context" as specified in sections 5.5.3.2.4 and 5.5.3.3.4.3 of 3GPP Release 10 TS 24.301 [17], sections 5.1.3.1 and L.2A.0 of 3GPP Release 10 TS 24.229 [15], and section 8.2 of 3GPP Release 10 TS 24.237 [16]. 

For IMS session termination of a Conversational Voice call, the dedicated bearer must be deleted utilising interaction with dynamic PCC. The network must initiate the deletion of the bearer. 

# 4.3.3 EPS Bearer Considerations for voice media on emergency PDN Connection

For an IMS session request for an emergency call on the PDN connection for emergency bearer services, and if as a result of SDP offer/answer a voice media is negotiated, then a dedicated bearer for voice media must be created by the network utilising interaction with dynamic PCC as specified in 3GPP Release 11 TS 23.401 [10]. The network must initiate the creation of a dedicated bearer to transport the voice media of an emergency call. The dedicated bearer for voice media of an emergency call: 

 must utilise the standardised QCI value of one (1); 

 must have the associated characteristics as specified in 3GPP TS 23.203 [4]; and 

 must have an ARP value that is reserved for emergency services. 

For IMS session termination of an emergency call, the dedicated bearer must be deleted utilising the interaction with dynamic PCC. The network must initiate the deletion of the bearer. 

# 4.4 P-CSCF Discovery

The UE and packet core must support the procedures for P-CSCF discovery via EPS. These are described in Annex L.2.2.1of 3GPP TS 24.229 [15], as option II for P-CSCF discovery. 

The UE must indicate P-CSCF IPv6 Address Request and P-CSCF IPv4 Address Request when performing the following procedures (see also section 4.3.1): 

 during the initial attach when establishing PDN connection to the default APN; 

during the initial attach when establishing PDN connection to the IMS well-known APN; 

during the establishment of the PDN connection to the IMS well-known APN when already attached; 

 during the attach procedure for emergency bearer services; and 

during the establishment of the PDN connection for emergency bearer services when already attached. 

The UE must use the P-CSCF addresses received during PDN connection establishment to the IMS well-known APN when accessing non-emergency services, and must use the P-CSCF addresses received during PDN connection establishment for emergency bearer services when accessing emergency services, as defined in section 5.1 of this document and 3GPP TS 24.229 [15]. 

If the UE receives a Modify EPS Bearer Context Request message containing a list of P-CSCF addresses that do not include the address of the currently used P-CSCF, the UE must acquire a P-CSCF different from the currently used P-CSCF and initiate a new initial registration as described in section L.2.2.1C 3GPP Release 12 TS 24.229. 

Note: The above behavior can result in any ongoing calls being released. 

# 5 Common Functionalities

# 5.1 IP Version

The UE and the network must support both IPv4 and IPv6 for all protocols that are used: SIP, SDP, RTP, RTCP and XCAP/HTTP. At initial attach and PDN connection establishment, the UE must request the PDN type IPv4v6, as specified in section 5.3.1.1 of 3GPP TS 23.401 [10] and section 6.2.2 of 3GPP TS 24.301 [17]. If both IPv4 and IPv6 addresses are assigned by the network to the UE, the UE must prefer the IPv6 address type when the UE discovers the P-CSCF. If only an IPv4 address or only IPv6 address is assigned by the network to the UE then the network must send ESM cause #50 "PDN type IPv4 only allowed" or #51 "PDN type IPv6 only allowed", respectively, to the UE and the UE must not request another PDN connection to the APN utilised in the initial attach or PDN connection establishment for the other IP version, as specified in section 6.2.2 of 3GPP Release 12 TS 24.301 [17]. 

After the UE has discovered the P-CSCF and registered to IMS with a particular IPv4 or IPv6 address, the UE must use this IP address for all SIP communication for as long as the IMS registration is valid. For all SDP and RTP/RTCP communication, the UE must use the IPv4 address used for SIP communication or an IPv6 address with the IPv6 prefix same as the IPv6 prefix of the IPv6 address used for SIP communication. 

Note: There are certain situations where interworking between IP versions is required. These include, for instance, roaming and interconnect between networks using different IP versions. In those cases, the network needs to provide the interworking in a transparent manner to the UE. 

# 5.2 Emergency Service

# 5.2.1 General

The UE and the network must support emergency services in the IMS domain. 

The UE and the network must support the IMS emergency services as specified in 3GPP Release 9 TS 24.229 [15], chapter 6 and Annex H of 3GPP Release 9 TS 23.167 [3], and emergency procedures as specified in 3GPP Release 9 TS 24.301 [17]. 

The UE must support the IMS emergency session specified in section 5.1.6.8.2 of 3GPP Release 14 TS 24.229 [15] (anonymous IMS emergency session), and the network can (dependent on operator policy) support the IMS emergency session procedures specified in section 5.2.10.2 and 5.2.10.5 of 3GPP Release 14 TS 24.229 [15]. 

The UE and the network must support the PDN disconnect procedure for emergency bearer services as described in section L.2.2.6.1 of 3GPP Release 14 TS 24.229 [15]. 

The UE must support the emerg-reg timer defined in table 7.8.1 of 3GPP Release 14 TS 24.229 [15] and related procedure defined in section 5.1.6.1 of 3GPP Release 14 TS 24.229 [15]. The operator can configure the UE with emerg-reg timer parameter as specified in Annex C3. 

If the UE: 

receives the Emergency Service Support indication during EPS attach or tracking area updating procedures; 

 attempts an emergency registration with IMS; 

receives a SIP 3xx, 4xx (except 401), 5xx or 6xx response to the emergency REGISTER request; and 

 is still in a tracking area that has received the Emergency Service Support indication; 

then the UE must perform the procedures defined in subclause 5.1.6.8.2 of 3GPP Release 14 TS 24.229 [15]. 

Note 1: No IMS emergency call is possible if the network does not support anonymous emergency sessions over IMS (e.g. because operator policy is restricted by local regulator) and when either 

 no agreement for national/international roaming exists, 

IMS emergency registration fails with an IMS emergency registration failure response 401, or 

 UE does not have sufficient credentials to authenticate with the IMS. 

When the UE has an ongoing emergency call, the UE must follow the procedures for access domain selection related to "Persistent EPS bearer context" as specified in sections 5.5.3.2.4 and 5.5.3.3.4.3 of 3GPP Release 10 TS 24.301 [17] and section 8.2 of 3GPP Release 10 TS 24.237 [16]. 

Recognizing that some network operators will continue a parallel CS network whilst their IMS network is deployed, and that support of emergency calls with CS support may be a local regulatory requirement, emergency calls in the CS domain are addressed in Annex A. 

The UE and network must support the 3GPP IM CN subsystem XML body as defined in section 7.6 of 3GPP TS 24.229 [15]. 

The usage of the 3GPP IM CN subsystem XML body in the network is an operator option. 

Note 2: This implies that the P-CSCF must support also the option that the XML body is not used. 

The SUPL enabled UE sends the emergency SUPL messages related to the UE detectable emergency session within the PDN connection for emergency bearer services. The SUPL enabled UE sends the emergency SUPL messages related to the non UE detectable emergency session within the PDN connection to the IMS well known APN. The UE selects the bearer to be used based on the TFTs of the bearers of the PDN connection. QCI of the selected bearer is provided by the network. 

# 5.2.2 Interactions between supplementary services and PSAP callback

The network must not invoke the use of supplementary services on a call identified as a PSAP callback as specified in 3GPP Release 12 TS 24.604 [20], 3GPP Release 12 TS 24.605 [21], 3GPP Release 12 TS 24.610 [25] and 3GPP Release 12 TS 24.611 [26]. 

Note: UE procedures for PSAP callback are not specified by 3GPP. 

# 5.2.3 UE location management

When initiating an IMS emergency session, the UE must conform to the requirements to convey its location, using the "Geolocation" header field and the PIDF location object in the initial SIP INVITE request, as specified in section 5.1.6.8.2 and section 5.1.6.8.3 of 3GPP TS 24.229 [5]. Furthermore, in the case of EN-DC (see section 4.2.5), the UE must use the access network information based on the primary cell of the Master RAN node (eNB) that is serving the UE for network location information as specified in section E.1.0 of 3GPP Release 15 of TS 23.228 [7]. 

Note: This applies regardless whether the IMS traffic is routed via the Master RAN node or the Secondary RAN node (gNB) or both. 

The support of URI that points to the location information is not required. 

# 5.3 Roaming Considerations

This profile has been designed to support IMS voice roaming. For more information on the IMS voice roaming models see GSMA PRD IR.65 [65] and GSMA PRD IR.88 [67]. 

# 5.4 Accesses in addition to E-UTRAN

UEs that support cellular (e.g. E-UTRAN) and non-cellular accesses that are not EPC-integrated (e.g. non-EPC integrated Wi-Fi access) must use: 

 the cellular access as transport of the Gm reference point; and 

the cellular access as transport of the Ut reference point, unless preconfigured otherwise by the home operator with the AccessForXCAP parameter as specified in Annex C.3. 

# 5.5 Data Off and Services Availability

# 5.5.1 General

The UE must and the network can support 3GPP PS Data Off. When 3GPP PS Data Off is activated by the user, the UE and the network must not send via any PDN connection any IP packet of any service other than 3GPP PS Data Off Exempt Services. This applies both to non-IMS based services and SIP-based IMS services. 

The UE must support to be provisioned with the list of SIP-based 3GPP PS Data Off Exempt Services as per section 5.67 of 3GPP Release 14 TS 24.167 [68] and section 5.7 of 3GPP Release 14 TS 24.275 [95]. 

The UE must support to be provisioned with the list of non-IMS 3GPP PS Data Off Exempt Services as per section 5.10i of Release 14 3GPP TS 24.368 [96] and 3GPP Release 14 TS 24.424 [91]. 

The UE must support to be provisioned for data off for the Call Composer service via the configuration parameter PRE AND POST CALL DATA OFF (see Annex C.3) as specified in section 2.8.1.5 of GSMA PRD RCC.07 [103]. 

A UE must report its 3GPP PS data off status, and each change in its 3GPP PS data off status as specified in 3GPP Release 14 TS 24.229 [15] and in section 6.3.10 and section 6.5.4.2 of 3GPP Release 14 TS 24.301 [17]. 

If the 3GPP PS data off status changes from "inactive" to "active" the UE must release all IMS sessions/dialogs that fulfil the conditions in section L.3.1.5 of 3GPP Release 14 TS 24.229 [15] 

Note: The UE can disconnect PDN connections that are not required by 3GPP PS Data Off Exempt Services. 

# 5.5.2 Supplementary Service Settings Management

The UE must be able to perform supplementary service settings management as described in section 2.3 regardless of whether 3GPP PS Data Off is active. For this reason, the operator must configure "IMS Supplementary Service configuration via the Ut interface using XCAP" as 3GPP PS Data Off Exempt Service, see section C.3. 

# 5.5.3 Voice Calls and SMS over IMS

The UE must be able to initiate and receive Voice Calls and SMS over IMS as described in the main body of this document regardless whether Data Off is active. For this reason, the operator must configure "MMTel Voice" and "SMS over IMS" as 3GPP PS Data Off Exempt Services, see section C.3. 

# 5.6 Voice Calls and Smart Congestion Mitigation

The UE must and the network can support Smart Congestion Mitigation as specified in section J.2.1.2 of 3GPP Release 12 TS 24.173 [14], section 5.6.1.6 and annex D of 3GPP Release 12 TS 24.301 [17], and sections 5.3.3.2, 5.3.3.10 and 5.3.3.11 of 3GPP Release 12 TS 36.331 [52]. 

# 5.7 Capability Discovery

The UE and the network can support Capability Discovery as defined in section 2.6 of GSMA PRD RCC.07 [103]. If Capability Discovery is supported by the UE and the network, then Capability Discovery is configured via the configuration parameter CAPABILITY DISCOVERY MECHANISM (see Annex C.3). Capability Discovery is enabled if the value of the configuration parameter CAPABILITY DISCOVERY MECHANISM is set to "0" or "1". 

If the UE supports Capability Discovery and if Capability Discovery is enabled, then the UE must follow the procedures for Capability Discovery as defined in GSMA PRD RCC.07 [103] and the procedures defined for the applicable services. 

In this version of the document, capability discovery is applicable for the following services: 

 Call Composer. 

# 5.8 HTTP Content Server

For the Call Composer service, the UE must support the procedures for file upload and file download to the HTTP Content Server. The network must provide a HTTP Content Server if the Call Composer service is enabled. 

The procedures for the file upload to the HTTP Content Server are defined in steps 1, 2, 3 and 4 of section 3.2.5.3.1.1 of GSMA PRD RCC.07 [103] and section 3.2.5.3.1.2 of GSMA PRD RCC.07 [103]. The operator can specify the HTTP Content Server for upload via the configuration parameter FT HTTP CS URI, see Annex C.3. 

The procedures for the file download from the HTTP Content Server are defined in sections 3.2.5.3.2 and 4.1.15.4 of GSMA PRD RCC.07 [103]. The operator can specify the HTTP Content Server for download via the configuration parameter FT HTTP DL URI, see Annex C.3. 

# Annex A Complementing IMS with CS

# A.1 General

In order to offer its customers a seamless service, the operator may wish to complement the IMS VoIP and SMSoIP capable radio coverage by using the CS radio access for voice, the SMS over NAS signalling on cellular access, or both. The IMS VoIP and SMSoIP coverage may be less or more extensive than the concurrent Circuit Switched (CS) coverage. This Annex describes the additional features that need to be implemented for the UEs and networks that wish to support such a deployment scenario. 

The voice related requirements in this annex are applicable if the UE has the setting of "IMS PS Voice preferred, CS Voice as secondary". 

# A.2 Domain Selection

The network and the UE must support the IMS voice over PS session supported indication as specified in section 4.3.5.8 of 3GPP TS 23.401 [10] 

The UE must perform voice domain selection for originating sessions with the setting of "IMS PS Voice preferred, CS Voice as secondary" as specified in section 7.2a of 3GPP TS 23.221 [6], and must perform the procedures defined in 3GPP TS 24.301 [10]. 

Note 1: The behaviour of UEs with the setting "IMS PS Voice preferred, CS Voice as secondary" is illustrated in Annex A.2 of 3GPP TS 23.221 [6]. 

The UE must perform voice domain selection and be able to retry in the CS domain (CSFB procedures) as defined in section 5.1.3.1 and Annex L.5 of 3GPP Release 14 TS 24.229 [15]. 

The network can support the rejection of a SIP INVITE as defined in section 5.2.7.2 of 3GPP release 14 TS 24.229 [15]. 

Note 2: The procedure in section 5.2.7.2 of 3GPP TS 24.229 can be used when the originating P-CSCF receives an indication that radio/bearer resources are not available and rejects the INVITE request with a SIP 500 (Server Internal Error) response. 

The UE must reject an incoming request if the UE is unable to support speech media on current PS access as specified in 3GPP TS 23.237 [8] and 3GPP TS 24.237 [16]. 

The UE must support Idle Mode Signalling Reduction (ISR) as specified in 3GPP Release 9 TS 23.401 [10] and 3GPP Release 9 TS 24.301 [17]. Therefore, the UE must disable ISR locally if IMS voice is supported in the network. 

# A.3 SR-VCC

The network must support the Single Radio Voice Call Continuity (SR-VCC) procedures for handover from E-UTRAN as described in 3GPP TS 23.216 [5] and 3GPP TS 23.237 [8]. 

The UE must support the SR-VCC procedures for single active call only as described in 3GPP TS 23.216 [5], 3GPP TS 24.008 [11], 3GPP TS 24.237 [16], and 3GPP TS 24.301 [17]. 

Note 1: The mechanisms to perform transfer of additional session / held state / conference call state / alerting calls are out of scope of the present version of this document. 

Note 2: UEs using IMS Centralized Services (ICS) capabilities are out of scope of the present version of this document. 

# A.4 IMS Voice service settings management when using CS access

The UE must use service setting management as defined in section 2.3.2 and section 5.5.1 using the current cellular access, over the APN defined in section 4.3.1. UEs that support non-cellular accesses that are not EPC-integrated (e.g. non-EPC integrated Wi-Fi access), must comply to the requirements of section 5.4. 

Note 1: This applies also when the UE is using CS network for voice service. 

If: 

 the UE attempts to perform supplementary service settings management via XCAP; 

the UE receives an HTTP failure code as described in section 5.3.1.2.2 of 3GPP Release 12 TS 24.623 [28]; 

the UE is not configured with SS_domain_setting parameter as specified in Annex C.3 with network operator's preference for the selection of the domain used by the UE when performing supplementary services setting control for voice services; and 

 until the UE performs a power-off/power-on or the UE detects a change of USIM/ISIM 

then: 

 the UE must not perform supplementary service settings management via XCAP; and 

the UE must instead attempt to perform supplementary service settings management in the CS domain. 

Note 2: By default, the UE is not configured with the SS_domain_setting parameter as specified in Annex C.3 with the network operator's preference for the selection of the domain used by the UE when performing supplementary service settings control for voice services. 

# A.5 Emergency Service

This section modifies the requirements defined in section 5.2 in the following ways: 

The UE must, and the network can, support the procedures and capabilities defined in section 5.2. 

If the support of one or more of the following scenarios is required, then the network must support the procedures in section 5.2: 

 Deployment scenarios where the IMS VoIP capable radio coverage is not complemented by CS radio coverage. 

 Provide voice service on LTE to UE with incompatible CS domain. 

 Provide voice service on LTE to UE supporting LTE only 

When emergency service support via CS domain is required, the UE and the network must support the CS emergency service as used today. 

The UE must be able to perform domain selection for emergency calls, and automatically be able to retry in the CS domain if a SIP INVITE for an IMS emergency session is rejected with a SIP 3xx, 4xx (except 407), 5xx or 6xx response, as defined in section 7.3 and Annex H of 3GPP Release 9 TS 23.167 [3] and 3GPP Release 9 TS 24.229 [15]. The UE must be able to detect if the network is not supporting IMS emergency sessions as defined in 3GPP TS 23.401 [10], then select the CS domain for UE detected emergency sessions. The UE must be able to perform domain selection for emergency calls, and also automatically be able to retry in the IMS if a UE detected CS emergency call attempt fails and the network supports IMS emergency sessions, as defined in subclause 7.3 and Annex H of 3GPP Release 9 TS 23.167 [3], 3GPP Release 9 TS 23.401 [10] and 3GPP Release 9 TS 24.229 [15]. 

The network must be able to reject a SIP INVITE for an IMS emergency session such that the UE can retry in the CS domain, as defined in 3GPP TS 24.229 [15] and section 6.2.1 of 3GPP TS 23.167 [3]. 

When IMS emergency service is not possible (e.g. the network does not support IMS emergency), and when the UE supporting CS Fallback (CSFB), as described in 3GPP TS 23.272 [9], is IMSI attached, then the UE must use the CSFB procedures for CS emergency service. If the network or the UE do not support CSFB, the UE must autonomously select the RAT that supports CS. 

The UE must support SR-VCC for IMS emergency sessions as specified in 3GPP Release 9 TS 23.216 [5] and 3GPP TS 23.237 [8]. The SR-VCC UE that supports IMS emergency service must support the SIP instance ID as defined in section 7.2 3GPP TS 24.237 [16]. 

The network must support SR-VCC for IMS emergency sessions as specified in 3GPP Release 9 TS 23.216 [5] and 3GPP TS 23.237 [8]. The network must support the SIP instance ID as defined in 3GPP TS 24.237 [16]. 

In limited service state, it is recommended that a UE that is CS voice capable should always camp on a RAT that is likely to support the CS domain, e.g. GERAN or UTRAN or CDMA2000, as described in 3GPP TS 23.221 [6]. 

# A.6 Roaming Considerations

When voice over IMS, see section 5.3, is not possible then the UE must follow the procedures defined in Annex A.2 to use CS for voice service. 

# A.7 SMS Support

This section modifies the requirements defined in section 2.5 in the following ways: 

The UE must, and the network can, support SMS-over-IP as described in section 2.5. In addition, when support of SMS over NAS signalling is required, the UE and the network must support the necessary procedures as specified in 3GPP TS 23.272 [9], 3GPP TS 23.221 [6] and 3GPP TS 24.301 [17]. If the UE supports both SMS-over-IP and SMS over NAS signalling methods, the UE must support the functionality as specified according to section 7.2c of 3GPP TS 23.221 [6]. The UE must: 

a) be pre-configured by the operator with the "SMS_Over_IP_Networks_Indication" parameter as specified in Annex C.3 that determines to use either SMS over IP or SMS over NAS signalling; and 

b) be capable of being configured according to the parameter "SMS_Over_IP_Networks_Indication" in the IMS Management Object defined in 3GPP TS 24.167 [68], in order to give operator control to configure the UE to use SMS over NAS signalling when required. 

The UE must only include the +g.3gpp.smsip feature tag as defined in section 5.3.2.2 of 3GPP TS 24.341 [19] in a SIP REGISTER request when 

"SMS_Over_IP_Networks_Indication" is set to the value of 1. 

If SMS over NAS signalling is not supported then the network must support the procedures in section 2.5. 

Note: SMS over NAS signalling without combined attach and without combined TA/LA update as specified in 3GPP Release 13 TS 23.272 [9] is out of scope of the present version of this document. 

# A.8 Call Waiting in the CS domain

When the UE on an ongoing call is presented with a new incoming call from the CS core network and: 

if the Communication Waiting supplementary service (see section 2.3.4) is deactivated in the UE, then the UE must reject the incoming call by sending a RELEASE COMPLETE message with cause #17 "user busy" as specified in 3GPP TS 24.008 [11]; and 

 if the Communication Waiting supplementary service is activated in the UE, the UE must generate a call waiting indication to the user. 

# A.9 USSD

For a UE that supports CSFB: 

If the UE has no ongoing IMS session for conversational voice calls and is not in the process of establishing an IMS session for conversational voice call (originated or terminated) then the UE must use the CSFB procedures as described in 3GPP TS 23.272 [9] for originating and terminating USSD requests in the CS domain. 

If the UE has one or more ongoing IMS sessions for conversational voice call or is in the process of establishing an IMS session for conversational voice call (originated or terminated) then: 

 the UE must not attempt originating USSD requests in the CS domain; and 

if paging procedure takes place, the UE must reject the request to perform CS fallback for terminating USSD requests as specified in 3GPP TS 24.301 [17]. 

# Annex B Features needed in certain regions

# B.1 General

This Annex describes features that operators need to support in certain regions due to local regulatory requirements. 

# B.2 Global Text Telephony over IP

In some regions, there are regulatory requirements that allows deaf/hearing impaired people to use text based communication known as Teletype Writer (TTY) to other users and government offices (e.g. to provide equal access to emergency services to all users). In this document, the evolution of the legacy CS-based TTY in IMS is referred to as Global Text Telephony over IP (GTT-IP). 

Note: GTT-IP is also referred to as Real Time Text in some standards. The use of GTT-IP in this section infers both GTT-IP and Real Time Text. 

The following requirements outline how the GTT-IP service should be implemented in regions where required. 

The UE must include the text media feature tag, as defined in IETF RFC 3840 [86], in the Contact header field of the SIP REGISTER request, in the Contact header field of the SIP INVITE request, and in the Contact header field of the SIP response to the SIP INVITE request, using procedures defined in 3GPP TS 24.229 [15]. 

GTT-IP messages must use ITU-T Recommendation T.140 [70] real-time text according to the rules and procedures specified in 3GPP TS 26.114 [35] with the following clarifications: 

The call with GTT-IP component must contain both "text" and "audio" media RTP streams negotiated using existing SDP offer/answer procedures. 

Note 2: The implementation of calls with single "text" media is not supported. 

For real-time text, RTCP reporting must be turned on by setting the SDP bandwidth modifiers "RS" and "RR" as specified in section 3.2.4. 

 The sampling time used must be 300 ms. 

 Change of the sampling time (rate adaptation) is not required. 

For an IMS session request for a call with GTT-IP component (originating and terminating), a dedicated bearer for the T.140 text media must be created by the network using interaction with dynamic PCC. The network must initiate the creation of a dedicated bearer to transport the text media. 

For a scenario when GTT-IP component is added or removed during the session, the existing dedicated bearer must be modified to add or to remove text media using interaction with dynamic PCC. 

The dedicated bearer for a call with GTT-IP component may use: 

a Non-GBR bearer with a QCI value of 8 or 9 as stated in annex E.4 of 3GPP Release 10 TS 26.114 [35]; or 

 a GBR bearer with a QCI value of 1. 

For networks residing in regions where regulatory requirements include requirements for low end-to-end latency and packet loss, the usage of a GBR bearer with a QCI of 1 for transport of both audio and real-time text RTP streams is recommended. 

There is no support of SR-VCC of T.140 text media (i.e. the T.140 text media is dropped after handover to CS). 

For IMS session release of a call with GTT-IP component, the dedicated bearer must be deleted by the network using interaction with dynamic PCC. The network must initiate the deletion of the bearer. 

# B.3 Service Specific Access Control

In some regions, e.g. Japan, there are regulatory requirements that require the need to release only voice calls while allowing high priority calls and access for other packet service (e.g. email, web, disaster message board), as under disaster or emergency events, the mass simultaneous voice call requests are usually the main cause for network congestion. 

To fulfil the regulatory requirements, the UE for such regions must support Service Specific Access Control (SSAC) as specified in 3GPP Release 9 TS 22.011 [1], 3GPP Release 9 TS 36.331 [52], 3GPP Release 9 TS 24.173 [14] and 3GPP Release 9 TS 27.007 [43]. 

# Annex C MNO provisioning and Late Customization

# C.1 General

This annex describes the capabilities to support MNO provisioning and late customization for the UE (e.g. for open market devices). An open market device: 

 Supports non-roaming and roaming cases; 

 Has a default configuration suitable for many MNOs; and 

 Can be configured to the MNO’s needs. 

# C.2 Configuration Methods

# C.2.1 Remote Client Configuration for MNO provisioning

The UE and the network must support one of the two configuration methods in order to support MNO provisioning for the parameters that are defined in 3GPP (see also Table C.3.1): 

 OMA DM V1.2 with http binding as specified in OMA-ERELD-DM-V1_2 [100]; or 

 Service provider device configuration as specified in GSMA PRD RCC.14 [93]. 

Note 1: The requirement on which configuration method to support may differ between regions. 

# C.2.2 Late Customization

The UE must support late customization as specified in GSMA PRD TS.32 [92] for the parameters that are in Table C.3.1 and can support late customization for the remaining parameters of GSMA PRD TS.32 [92]. 

# C.1 Configuration Parameters

Table C.3.1 contains configuration parameters with their default values that must be supported by the UE and the network. The UE must use the default value for each parameter in Table C.3.1 unless configured differently by any of the methods as described in section C.2. 

Note: The parameters in Table C.3.1 are a subset of parameters in section 3.8 of GSMA PRD TS.32 [92]. 

<table><tr><td>Parameter</td><td>Default value</td><td>Defined in</td><td>See also clause</td></tr><tr><td>IMS</td><td>0-Enabled</td><td>Section 5.13 of 3GPP TS 24.305 [18] as /&lt;X&gt;/IMS</td><td>2.2.1</td></tr><tr><td>Media_type_restriction_policy (Voice and/or Video over LTE allowed)</td><td>Voice only allowed</td><td>Section 5.43 of 3GPP Release 14 TS 24.167 [68] (interior node /&lt;X&gt;/Media_type_restriction_policy) and 3GPP Release 14 TS 24.229 [15]</td><td>2.2.1</td></tr><tr><td>Media_type_restriction_policy(Voice and/or Video over LTE allowed while roaming)</td><td>Voice Prohibited</td><td>Section 5.43 and 5.48 of 3GPP Release 14 TS 24.167 [68] (interior node [/X&gt;/Media_type_restriction_policy and leaf [/X&gt;/Roaming) and 3GPP Release 14 TS 24.229 [15]</td><td>2.2.1, 5.3</td></tr><tr><td>SMSoIP_USAGE_policy(When to use SMSoIP)</td><td>2 - SMSoIP irrespective of IMS voice support</td><td>Section 5.71 of 3GPP Release 14 TS 24.167 [68] (/[X]/SMSoIP_USAGE_policy)</td><td>2.2.1</td></tr><tr><td>RegRetryBaseTime</td><td>30 Sec</td><td>Section 5.35 of 3GPP TS 24.167 [68] (/[X]/RegRetryBaseTime)</td><td>2.2.1</td></tr><tr><td>RegRetryMaxTime</td><td>1800 sec</td><td>Section 5.35 of 3GPP TS 24.167 [68] (/[X]/RegRetryMaxTime)</td><td>2.2.1</td></tr><tr><td>Policy_on_localNumbers(Local number type for voice and video calls)</td><td>1 -Home-local number</td><td>Section 5.62 of 3GPP Release 14 TS 24.167 [68] (/[X]/Policy_on_localNumbers)</td><td>2.2.3.2</td></tr><tr><td>Timer_T1</td><td>2 sec</td><td>Section 5.10 of 3GPP TS 24.167 [68] (/[X]/Timer_T1)</td><td>2.2.4</td></tr><tr><td>Timer_T2</td><td>16 sec</td><td>Section 5.11 of 3GPP TS 24.167 [68] (/[X]/Timer_T2)</td><td>2.2.4</td></tr><tr><td>Timer_T4</td><td>17 sec</td><td>Section 5.12 in 3GPP TS 24.167 [68] (/[X]/Timer_T4)</td><td>2.2.4</td></tr><tr><td>Reliable 18x policy(Sending SIP 18x reliably)</td><td>1 - Indicates that the SIP 18x responses (other than SIP 183 response) are to be sent reliably</td><td>Section 5.56 of 3GPP Release 14 TS 24.167 [68] (/[X]/ Reliable_18x_policy [/X]/ Send_18x_Reliably) and 3GPP Release 14 TS 24.229 [15]</td><td>2.2.4</td></tr><tr><td>XCAP Root URI</td><td>No default</td><td>3GPP TS 24.623 [28]</td><td>2.3.2</td></tr><tr><td>Conf_Factory_URI(Conference Factory URI)</td><td>None</td><td>Section 5.4 of 3GPP TS 24.166 [88] (/[X]/Conf_Factory_URI)</td><td>2.3.3</td></tr><tr><td>FromPreferred</td><td>0 - From header field; is not used for determinatio n of the originating party identity in OIP service</td><td>3GPP Release 14 TS 24.607 [23] and section 5.4 of 3GPP Release 14 TS 24.417 [90] (/[X]/FromPreferred)</td><td>2.3.12</td></tr><tr><td>Precondition_disabling_policy(SIP Preconditions used)</td><td>0 – the UE is allowed to use the precondition mechanism</td><td>Section 5.60 of 3GPP Release 14 TS 24.167 [68](/&lt;X&gt;/Precondition_disabling_policy) and 3GPP Release 14 TS 24.229 [15]</td><td>2.4.1</td></tr><tr><td>Default_EPS_bearer_context_uusage_restriction_policy(Voice Media on default (QCI=5) bearer)</td><td>Prohibited</td><td>Section 5.49 of 3GPP Release 14 TS 24.167 [68] (interior node /&lt;X&gt;/Default_EPS_bearer_context_usa ge_restriction_policy) and 3GPP Release 14 TS 24.229 [15]</td><td>2.4.3.1</td></tr><tr><td>RateSet for AMR</td><td>0,2,4,7 ("mode-set = 0,2,4,7" included in the SDP answer)</td><td>Defined in clause 15.2 of 3GPP Release 9 TS 26.114 [35](/&lt;X&gt;/Speech/&lt;X&gt;/RateSet) with (/&lt;X&gt;/Speech/&lt;X&gt;/Codec="amr")</td><td>2.4.3.2</td></tr><tr><td>RateSet for AMR-WB</td><td>Undefined (no mode-set parameter included in the SDP answer)</td><td>Defined in clause 15.2 of 3GPP Release 9 TS 26.114 [35](/&lt;X&gt;/Speech/&lt;X&gt;/RateSet) (/&lt;X&gt;/Speech/&lt;X&gt;/Codec="amr-wb")</td><td>2.4.3.2</td></tr><tr><td>EVS/Br</td><td>5.9-24.4</td><td>Defined in clause 15.2 of 3GPP Release 13 TS 26.114 [35](/&lt;X&gt;/Speech/&lt;X&gt;/EVS/Br) and clause 5 of 3GPP Release 13 TS 26.441 [76] (Table 1)</td><td>2.4.3.3</td></tr><tr><td>EVS/Bw</td><td>nb-swb</td><td>Defined in clause 15.2 of 3GPP Release 13 TS 26.114 [35](/&lt;X&gt;/Speech/&lt;X&gt;/EVS/Bw)</td><td>2.4.3.3</td></tr><tr><td>ICM/INIT_PARTIAL_REDUNDANCY_OFFSET_RECV</td><td>undefined (ch-aw-recv not included in SDP offer)</td><td>Defined in clause 17.2 of 3GPP Release 13 TS.26.114 [35] /&lt;X&gt;/Speech/&lt;X&gt;/ICM/INIT_PARTIAL_REDUNDANCY_OFFSET_RECV</td><td>2.4.3.3</td></tr><tr><td>ToConRef (Network Identifier part of the HOS APN)</td><td>Internet APN</td><td>Section 5.9 of 3GPP Release 14 TS 24.424 [91](/&lt;X&gt;/XCAP conn.params_policy/&lt;X&gt;/XDM_MO_ref) and 3GPP Release 14 TS 24.623 [28]</td><td>4.3.1</td></tr><tr><td>EPS_initial Attached_ConRefs (APN in initial attach)</td><td>No APN</td><td>Section 5.57 of 3GPP Release 14 TS 24.167 [68] (interior node /&lt;X&gt;/EPS初始 Attached_ConRefs) and 3GPP Release 14 TS 24.229 [15]</td><td>4.3.1</td></tr><tr><td>AccessForXCAP</td><td>1 - 3GPP accesses only</td><td>3GPP TS 24.424 [89] and section 5.2.1.3 of 3GPP Release 14 TS 24.623 [28] (/&lt;X&gt;/AccessForXCAP)</td><td>5.4</td></tr><tr><td>SS_XCAP_config_exempt</td><td>1 - Indicates that the SS configuration via XCAP is a 3GPP PS data off exempt service</td><td>Section 5.11 of 3GPP TS 24.424 [91] (/&lt;X&gt;/3GPP_PS_data_off/SS_XCAP_c config_exempt).</td><td>5.5.2</td></tr><tr><td>MMTEL Voice_exempt</td><td>1 - Indicates that the MMTEL voice is a 3GPP PS data off exempt service</td><td>Section 5.7 of 3GPP TS 24.275 [95] (/&lt;X&gt;/3GPP_PS_data_off/MMTEL voic e_exempt)</td><td>5.5.3</td></tr><tr><td>SMSOP_exempt</td><td>1 - Indicates that the SMS over IP is a 3GPP PS data off exempt service</td><td>Section 5.67 of 3GPP TS 24.167 [68] (/&lt;X&gt;/3GPP_PS_data_off/SMSoIP_exempt)</td><td>5.5.3</td></tr><tr><td>SS_domain_settings</td><td>No default</td><td>Section 5.41 of 3GPP Release 12 TS 24.167 [68] (/&lt;X&gt;/SS_domain_settings)</td><td>A.4</td></tr><tr><td>SMS_Over_IP_Networks_Indica tion</td><td>1 - SMS service is preferred to be invoked over the IP networks</td><td>Section 5.28 of 3GPP TS 24.167 [68] (/&lt;X&gt;/SMS_Over_IP_Networks_Indicati on)</td><td>A.7</td></tr><tr><td>Device_management_over_PS</td><td>1 - Indicates that the device management over PS is a 3GPP PS data off exempt service</td><td>Section 5.10i of 3GPP TS 24.368 [96] (/&lt;X&gt;/3GPP_PS_data_off/Exempted_se rvice_list/&lt;X&gt;/Device_management_ove r_PS)</td><td>C.2</td></tr></table>

<table><tr><td>Parameter</td><td>Default value</td><td>Defined in</td><td>See also clause</td></tr><tr><td>USSI_exempt</td><td>1 - Indicates that USSI is a 3GPP PS data off exempt service</td><td>Section 5.4B of 3GPP Release 14 TS 24.391 [99] (/&lt;X&gt;/3GPP_PS_data_off/USSI_exempt)</td><td></td></tr><tr><td>emerg-reg</td><td>10 sec</td><td>Section 5.61 of 3GPP Release 14 TS 24.167 [68] (/&lt;X&gt;/TimerEmerg-reg)</td><td>5.2.1</td></tr><tr><td>COMPOSER AUTH</td><td>0 - Indicates that Call Composer service is disabled</td><td>Section 2.1.2 of RCC.20 [106] (/&lt;X&gt;/Services/composerAuth)The values &quot;2&quot; and &quot;3&quot; indicate that the Call Composer service is enabled.If the value &quot;3&quot; is configured and the UE only supports Call Composer, the UE must behave as defined for a value of &quot;2&quot;.If any other value is configured, the UE must behave as defined for a value of &quot;0&quot;.</td><td>2.3.14</td></tr><tr><td>FT HTTP CS URI</td><td>As defined in section A.1.4 of RCC.07 [103]</td><td>Section A.2.4 of RCC.07 [103](/&lt;X&gt;/Messaging/FileTransfer/ftHTTPC URI)</td><td>2.3.13</td></tr><tr><td>FT HTTP DL URI</td><td>No default</td><td>Section A.2.4 of RCC.07 [103](/&lt;X&gt;/Messaging/FileTransfer/ftHTTPLURI)</td><td>2.3.13</td></tr><tr><td>FT HTTP CS USER</td><td>No default</td><td>Section A.2.4 of RCC.07 [103](/&lt;X&gt;/Messaging/FileTransfer/ftHTTPC SUser)</td><td>2.2.2</td></tr><tr><td>FT HTTP CS PWD</td><td>No default</td><td>Section A.2.4 of RCC.07 [103](/&lt;X&gt;/Messaging/FileTransfer/ftHTTPC SPwd)</td><td>2.2.2</td></tr><tr><td>PRE AND POST CALL DATA OFF</td><td>1 - indicates that Call Composer services are cellular data off exempt services</td><td>Section A.2.2 of RCC.07 [103](/&lt;X&gt;/Services/Ext/DataOff/preAndPost CallDataOff)</td><td>5.5.1</td></tr><tr><td>CAPABILITY DISCOVERY MECHANISM</td><td>2 - OFF</td><td>Section A.2.5 of RCC.07 [103](/&lt;X&gt;/CapDiscovery/defaultDisc)</td><td>5.7</td></tr></table>


Table C.3.1 Configuration parameters and their default values


# 6 Annex D USSI

# D.1 Introduction

# D.1.1 Overview

The support of USSI is optional for both the UE and the Network. This Annex describes the additional functionalities that need to be implemented for the UEs and networks that do support USSI. The scope includes the following aspects: 

 IMS basic capabilities [Chapter D.2] 

 Media negotiation [Chapter D.3] 

 Functionality that is relevant across the protocol stack and subsystems [Chapter D.4] 

Additional features that need to be implemented for the UEs and networks that wish to support concurrent CS coverage [Chapter D.5] 

This Annex is applicable for a scenario where IMS is deployed without relying on any CS infrastructure. In this case the UEs and networks must be compliant with all of the normative statements in this Annex. 

Chapter D.5 defines the profile for an alternative approach where USSD is deployed with a certain degree of reliance on an existing 3GPP CS network infrastructure. 

In this version of the PRD, only voice-capable UEs and networks are considered. 

# D.2 IMS Feature Set

# D.2.1 General

This Annex lists the additional mandatory capabilities compared to the main body and Annex A that are required over the Gm reference point. 

# D.2.2 Support of generic IMS functions

# D.2.2.1 General

The UE and the network must fulfil the requirements for addressing as specified in section 4.5.4.1 of 3GPP Release 12 TS 24.390 [98]. 

Note: Geo-local numbering is not used in USSI. 

# D.2.2.2 SIP Registration Procedures

A UE must perform a SIP Registration as specified in 2.2.1 and must include a g.3gpp.nw-init-ussi media feature tag in the Contact header field as specified in 3GPP Release 12 TS 24.390 [98]. 

# D.2.3 USSI Considerations

# D.2.3.1 General

The following sub-sections provide considerations for the UE and network specific to USSI. 

# D.2.3.2 UE initiated

The UE must support the invocation and operation of user initiated USSI as defined in sections 4.5.4.1 and 4.5.3 of 3GPP Release 12 TS 24.390 [98]. 

The USSI AS (USSI Application Server) must support the actions defined in section 4.5.4.2 of 3GPP Release 12 TS 24.390 [98]. 

# D.2.3.3 Network initiated

The USSI AS may support the invocation and operation of network initiated USSI as defined in section 4.5.5.1 of 3GPP Release 12 TS 24.390 [98]. 

The UE must support the actions defined in section 4.5.5.2 of 3GPP Release 12 TS 24.390 [98]. 

# D.3 SDP negotiation

The UE and the IMS core network must support the SDP negotiation to not use media resources for UE initiated USSI and network initiated USSI as described in sections 4.5.2 and 4.5.2A (respectively) of 3GPP Release 12 TS 24.390 [98]. 

# D.4 Common Functionalities

# D.4.1 Data Off

The UE must fulfil the requirements as specified in section 5.5.1. 

The UE must be able to initiate and receive USSI messages as described in this Annex regardless whether 3GPP PS (Packet Switched) Data Off is active i.e. the UE continues to use (does not disconnect) the PDN connection via the IMS well-known APN. For this reason, the operator must configure "USSI_exempt" as 3GPP PS Data Off Exempt Services, see section C.3. 

# D.5 Complementing IMS with CS

# D.5.1 General

In order to offer its customers a seamless service, the operator may wish to complement the USSI capable radio coverage by utilising the CS radio access and/or the CS core network for USSD. The USSI capable radio coverage may be less or more extensive than the CS/USSD coverage. These clauses describe the additional features that need to be implemented for the UEs and networks that wish to support such a deployment scenario. 

The UE and the network must support the necessary procedures as specified in 3GPP Release 12 TS 23.090 [97]. 

# D.5.2 Domain Selection

The UE must support the selection of an appropriate method for UE originating USSD request delivery as specified in section 7.2e of 3GPP Release 12 TS 23.221 [6]. The support of the USSI Management Object as defined in 3GPP Release 12 TS 24.391 [99] by the UE and network is not required. 

Note: When the originating voice domain selection is PS, the absence of support in the UE of the Management Object defined in 3GPP Release 12 TS 24.391 [99] provides as a result, the UE to send an originating USSD request using IMS according to 3GPP Release 12 TS 24.390 [98]. If the home network does not support USSI and in order to ensure the correct delivery of UE initiated USSD requests (i.e. via CS), the home network needs to ensure that USSI requests are rejected with a 404 (Not found) response as specified in 3GPP Release 12 TS 24.390 [98]. 

The UE must support the selection of an appropriate method for UE terminating USSD request delivery as specified in section 7.2b of 3GPP Release 12 TS 23.221 [6]. 

If USSD (via the CS network) is used, then the procedures of Annex A.9 shall be applicable. 

# Annex D Document Management


D.1 Document History


<table><tr><td>Version</td><td>Date</td><td>Brief Description of Change</td><td>Approval Authority</td><td>Editor / Company</td></tr><tr><td>0.1</td><td>28/01/2010</td><td>New PRD (RILTE Doc 06/004).</td><td>RILTE #6</td><td>John Boggis, Vodafone</td></tr><tr><td>0.2</td><td>19/02/2010</td><td>Updated to take account of changes proposed by Itsuma Tanaka from NTT Docomo</td><td>RILTE (email approval after Mtg #6)</td><td>John Boggis, Vodafone</td></tr><tr><td>1.0</td><td>18/03/2010</td><td>DAG #67 comments</td><td>IREG email approval before mtg # 58 EMC # 81</td><td>John Boggis, Vodafone</td></tr><tr><td>2.0</td><td>29/07/2010</td><td>CR001 to IR.92 Enhancements and corrections to the document</td><td>IREG email approval before mtg # 59 EMC # 86</td><td>John Boggis, Vodafone</td></tr><tr><td>3.0</td><td>22/12/2010</td><td>CR002 to IR.92 Enhancements and corrections to the document</td><td>IREG # 59 EMC # 89</td><td>John Boggis, Vodafone</td></tr><tr><td>4.0</td><td>22/3/2011</td><td>Implementation of CR003, CR004, CR005 and CR006.</td><td>RILTE/IREG email approval before IREG #60 EMC # 91</td><td>John Boggis, Vodafone</td></tr><tr><td>5.0</td><td>28/12/2011</td><td>Implementation of CR007 to CR015.</td><td>RILTE/IREG email approval before IREG #61 EMC # 99</td><td>John Boggis, Vodafone</td></tr><tr><td>6.0</td><td>28/12/2011</td><td>Implementation of CR016 and CR017</td><td>IREG #62 PSMC # 102</td><td>John Boggis, Vodafone</td></tr><tr><td>7.0</td><td>25/02/2013</td><td>Implementation of CR1001, CR1002, CR1003 and CR1004.</td><td>IREG #63</td><td>Nick Russell, RIM Ltd.</td></tr><tr><td>7.1</td><td>10/09/2013</td><td>Implementation of CR1005</td><td>IREG RILTE #32</td><td>Nick Russell, BlackBerry Ltd.</td></tr><tr><td>8.0</td><td>07/04/2014</td><td>Implementation of CR1006, CR1008, CR1009, CR1011, CR1012, CR1013, CR1015, CR1016, CR1018, CR1019, CR1020, CR1021, CR1022, CR1023, CR T9, CR T10, and CR T14</td><td>IREG RILTE #37 and IREG #66</td><td>Nick Russell, BlackBerry Ltd.</td></tr><tr><td>9.0</td><td>02/04/2015</td><td>Implementation of CR1024, CR1025, CR1027, CR1029, CR1030, CR1031, CR1032, CR1033, CR1034, CR1035, CR1036, CR1037, CR1038, CR1039, CR1040, CR1041, CR1042, CR1043, CR1044, CR1045, CR1046, CR1047, CR1048, CR1051, CR1052, CR1055, CR1056, and CR1059.</td><td>NG #1</td><td>Nick Russell, BlackBerry Ltd.</td></tr><tr><td>10.0</td><td>19/05/2016</td><td>Implementation of CR1063, CR1060, CR1067, CR1064, CR1065, CR1068 (IR92CR46MeEl1), CR1069, CR1072 CR1071, CR1070, CR1076, CR1077, CR1073, CR1075, CR1078, CR1074, CR1066, CR1079, CR1081, CR1087, CR1090, CR1082, CR1083, CR1080, CR1088, CR1089, CR1084, CR1086, CR1085, CR1091, CR1092, CR1093, CR1094, CR1095, CR1097, CR1101, CR1102, CR1103, CR1104, CR1096, CR1098, CR1099, CR1105, CR1106, CR1108, CR1110.</td><td>NG #3</td><td>Nick Russell, BlackBerry Ltd.</td></tr><tr><td>11.0</td><td>15/06/2017</td><td>Implementation of CR1111, CR1112, CR1113, CR1114, CR1115, CR1116, CR1117, CR1118, CR1119, CR1120, CR1122, CR1123, CR1124, CR1125, CR1126, CR1127, CR1128, CR1129, CR1130, CR1131, CR1132, CR1133, CR1134, CR1135, CR1136, CR1137, CR1138, CR1139, CR1140, CR1141, CR1143, CR1145, CR1146, CR1147 and CR1148</td><td>NG #5</td><td>Nick Russell (BlackBerry Ltd.), Keith Drage (Nokia).</td></tr><tr><td>12.0</td><td>02/05/2018</td><td>Implementation of CR1149, CR1150, CR1151, CR1152, CR1153, CR1154, CR1155, CR1156, CR1157, CR1158, CR1159, CR1160, CR1161, CR1162, CR1163</td><td></td><td>Mari Melander (Telekom Deutschland GmbH)</td></tr><tr><td>13.0</td><td>17/04/2019</td><td>Implementation of CR1164, CR1165, CR1167, CR1168, CR1169, CR1170, CR1171, CR1172, CR1173, CR1174, CR1175, CR1176, CR1177, CR1179, CR1180, CR1181, CR1182, CR1183, CR1184, CR1185 and CR1186</td><td></td><td>Mari Melander (Telekom Deutschland GmbH), Haitao Wei (Huawei)</td></tr></table>

# D.2 Other Information

<table><tr><td>Type</td><td>Description</td></tr><tr><td>Document Owner</td><td>NG RILTE</td></tr></table>

Editor / Company 

Haitao Wei, Huawei 

It is our intention to provide a quality product for your use. If you find any errors or omissions, please contact us with your comments. You may notify us at prd@gsma.com 

Your comments or suggestions & questions are always welcome. 