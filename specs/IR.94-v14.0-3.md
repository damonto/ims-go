![image](https://cdn-mineru.openxlab.org.cn/result/2026-03-11/4c38ba4f-2034-4daa-9c2c-b28e30d65684/f33638124130995988e245c8bbf5380f6be3fc632619b297f415389ab544f73f.jpg)


# IMS Profile for Conversational Video Service

Version 14.0 

17 April 2019 

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

# 1 Introduction 4

1.1 Overview 4 

1.2 Relationship to 3GPP Specifications 4 

1.3 Scope 5 

1.4 Definition of Acronyms and Terms 5 

1.5 Document Cross-References 7 

# 2 IMS Feature Set 8

2.1 General 8 

2.2 Support of Generic IMS Functions 8 

2.2.1 SIP Registration Procedures 8 

2.2.1a Addressing 8 

2.2.2 Call Establishment and Termination 8 

2.2.3 Early Media 10 

2.2.4 SIP OPTIONS 10 

2.3 Supplementary Services 10 

2.3.1 General 10 

2.3.2 Communication Hold 10 

2.3.3 Ad-Hoc Multi Party Conference 10 

2.4 Call Set-up Considerations for Calls with Video Media 11 

2.4.1 Integration of Resource Management and SIP 11 

2.4.2 Video Media Considerations 11 

2.4.3 SIP Precondition Considerations 12 

2.5 User-Agent and Server Headers 12 

# 3 IMS Media 12

3.1 General 

3.2 Voice Media 12 

3.3 Video Media 12 

3.3.1 Video Codec 12 

3.3.2 RTP Profile and Data Transport 14 

3.3.3 RTCP Usage 15 

3.3.4 RTP Payload Format Considerations for Video 16 

# 4 Radio and Packet Core Feature Set for Video 16

4.1 General 16 

4.2 Bearer Considerations for Video 16 

4.2.1 E-UTRAN 16 

4.3 LTE Radio Capabilities 16 

# 5 Common Functionalities 17

5.1 Data Off and Services Availability 17 

5.2 Capability Discovery 17 

# Annex A Complementing IMS with CS 18

A.1 General 18 

A.2 SR-VCC 18 

# Annex B Features needed in certain regions 19

B.1 General 19 

B.2 Video media in emergency service 19 

# Annex C MNO Provisioning and Late Customization 20

C.1 General 20 

C.2 Configuration Methods 20 

C.3 Configuration Parameters 20 

# Annex D Document Management 22

D.1 Document History 22 

Other Information 23 

# 1 Introduction

# 1.1 Overview

The IP Multimedia Subsystem (IMS) Profile for Conversational Video Service, documented in this Permanent Reference Document (PRD), defines a minimum mandatory set of features which are defined in 3GPP specifications that a wireless device and a network are required to implement to guarantee an interoperable, high quality IMS-based conversational video service over Long Term Evolution (LTE) radio access. The content includes the following aspects: 

 IMS basic capabilities and supplementary services for telephony [Chapter 2]. 

 Real-time media negotiation, transport, and codecs [Chapter 3]. 

 LTE radio and evolved packet core capabilities [Chapter 4]. 

 Functionality that is relevant across the protocol stack and subsystems [Chapter 5]. 

Additional features that need to be implemented for the UEs and networks that wish to support concurrent Circuit Switched (CS) coverage [Annex A]. 

Additional features that only a subset of the IMS telephony operators needs to support in certain markets [Annex B]. 

UE configuration to provide all necessary information to connect to, and receive voice service and SMS from, a specific IMS telephony operator [Annex C]. 

Going forward, IMS-based conversational video service over High-Speed Packet Access (HSPA) radio access won’t be maintained. 

The minimum mandatory set of features is defined by listing the features for the video service over LTE that are required on top of the features defined in GSMA PRD IR.92 [1] for voice and SMS. 

The conversational video services comprise calls with full duplex voice and simplex/fullduplex video media with tight synchronization between the constituent streams. The call can be a point to point call or a multiparty conference call. The conversational video service can also be used to interact with for example dial in video conference systems. 

Note: The term “video call” is used in this document as shorthand for a service or call with both voice and video media. 

# 1.2 Relationship to 3GPP Specifications

This profile is solely based on the open and published 3GPP specifications as listed in the Section 1.5 or in the IR.92 [1]. 3GPP Release 8, the first release supporting LTE, is taken as a basis. It should be noted, however that not all the features mandatory in 3GPP Release 8 for video services are required for compliance with this profile. 

Conversely, some features required for compliance with this profile are based on functionality defined in 3GPP Release 10. All such exceptions are explicitly mentioned in the following sections along with the relevant Release 8 or higher 3GPP release specifications, respectively. 

Unless otherwise stated, the latest version of the referenced specifications for the relevant 3GPP release applies. 

# 1.3 Scope

This document defines an IMS profile by listing a number of Evolved Universal Terrestrial Radio Access Network (E-UTRAN), Evolved Packet Core, IMS core, and User Equipment (UE) features which are considered essential to launch interoperable IMS based conversational video service as defined in the introduction in section 1.1. Sessions with asymmetric media streams or video-only sessions are outside the scope of the present document. 

The scope of the profile, in this version, is the interface between UE and network. 

Note 1: Although, this version of the specification focuses on E-UTRAN, the defined IMS functionalities can be applied to other IP Connectivity Accesses. 

If the use of conversational video services is disabled in the UE e.g. by the user or network, requirements described in this document do not apply. 

Note 2: The ability for the user to disable conversational video services in the UE is a UE implementation option. 

Note 3: Disabling conversational video services in the UE by the network, at the discretion of the home operator, is currently outside the scope of this document. 

The profile does not limit anyone, by any means, to deploy other standardized features or optional features, in addition to the defined profile. 

# 1.4 Definition of Acronyms and Terms

<table><tr><td>Term</td><td>Description</td></tr><tr><td>3GPP</td><td>3rd Generation Partnership Project</td></tr><tr><td>AM</td><td>Acknowledged Mode</td></tr><tr><td>AVC</td><td>Advanced Video Coding</td></tr><tr><td>AVP</td><td>Audio Video Profile</td></tr><tr><td>AVPF</td><td>Audio Visual Profile with Feedback</td></tr><tr><td>CBP</td><td>Constrained Baseline Profile</td></tr><tr><td>CCM</td><td>Codec Control Message</td></tr><tr><td>CHP</td><td>Constrained High Profile</td></tr><tr><td>CNAME</td><td>Canonical End-Point Identifier SDES Item</td></tr><tr><td>CVO</td><td>Coordination of Video Orientation</td></tr><tr><td>DRB</td><td>Data Radio Bearer</td></tr><tr><td>eNB</td><td>eNodeB</td></tr><tr><td>EPS</td><td>Evolved Packet System</td></tr><tr><td>E-UTRAN</td><td>Evolved Universal Terrestrial Radio Access Network</td></tr><tr><td>FIR</td><td>Full Intra Request</td></tr><tr><td>GBR</td><td>Guaranteed Bit Rate</td></tr><tr><td>HEVC</td><td>High Efficiency Video Coding</td></tr><tr><td>HSPA</td><td>High-Speed Packet Access</td></tr><tr><td>IDR</td><td>Instantaneous Decoding Refresh</td></tr><tr><td>ICSI</td><td>IMS Communication Service Identifier</td></tr><tr><td>IETF</td><td>Internet Engineering Task Force</td></tr><tr><td>IMS</td><td>IP Multimedia Subsystem</td></tr><tr><td>IP</td><td>Internet Protocol</td></tr><tr><td>IRAP</td><td>Intra Random Access Point</td></tr><tr><td>LTE</td><td>Long Term Evolution</td></tr><tr><td>MRFP</td><td>Media Resource Function Processor</td></tr><tr><td>NACK</td><td>Negative Acknowledgment</td></tr><tr><td>PCC</td><td>Policy and Charging Control</td></tr><tr><td>PCRF</td><td>Policy and Charging Rules Function</td></tr><tr><td>P-CSCF</td><td>Proxy - Call Session Control Function</td></tr><tr><td>PLI</td><td>Picture Loss Indication</td></tr><tr><td>PDP</td><td>Packet Data Protocol</td></tr><tr><td>PPS</td><td>Picture Parameter Sets</td></tr><tr><td>PRD</td><td>Permanent Reference Document</td></tr><tr><td>PS</td><td>Packet Switched</td></tr><tr><td>QCI</td><td>Quality of Service Class Indicator</td></tr><tr><td>QOS</td><td>Quality of Service</td></tr><tr><td>RR</td><td>Receiver Report RTCP Packet</td></tr><tr><td>RAB</td><td>Radio Access Bearer</td></tr><tr><td>RAT</td><td>Radio Access Technology</td></tr><tr><td>Region</td><td>As defined in GSMA PRD IR.92</td></tr><tr><td>RFC</td><td>Request For Comment</td></tr><tr><td>RTCP</td><td>RTP Control Protocol</td></tr><tr><td>RTP</td><td>Real-Time Transport Protocol</td></tr><tr><td>SDES</td><td>Session Descriptor RTCP Packet</td></tr><tr><td>SDP</td><td>Session Description Protocol</td></tr><tr><td>SIP</td><td>Session Initiation Protocol</td></tr><tr><td>SMS</td><td>Short Message Service</td></tr><tr><td>SPS</td><td>Sequence Parameter Sets</td></tr><tr><td>SR</td><td>Sender Report</td></tr><tr><td>SRB</td><td>Signalling Radio Bearer</td></tr><tr><td>TMMBN</td><td>Temporary Maximum Media Stream Bit Rate Notification</td></tr><tr><td>TMMBR</td><td>Temporary Maximum Media Stream Bit Rate Request</td></tr><tr><td>UE</td><td>User Equipment</td></tr><tr><td>UM</td><td>Unacknowledged Mode</td></tr></table>

# 1.5 Document Cross-References

<table><tr><td>Ref</td><td>Document Number</td><td>Title</td></tr><tr><td>1</td><td>GSMA PRD IR.92</td><td>IMS Profile for Voice and SMS.</td></tr><tr><td>2</td><td>GSMA PRD IR.58</td><td>IMS profile for voice over HSPA</td></tr><tr><td>3</td><td>3GPP TS 23.203</td><td>Policy and charging control architecture</td></tr><tr><td>4</td><td>3GPP TS 24.147</td><td>Conferencing using the IP Multimedia (IM) Core Network (CN) subsystem; Stage 3</td></tr><tr><td>5</td><td>3GPP TS 24.229</td><td>IP multimedia call control protocol based on Session Initiation Protocol (SIP) and Session Description Protocol (SDP); Stage 3</td></tr><tr><td>6</td><td>3GPP TS 26.114</td><td>IP Multimedia Subsystem (IMS); Multimedia telephony; Media handling and interaction</td></tr><tr><td>7</td><td>3GPP TS 36.331</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA); Radio Resource Control (RRC); Protocol specification</td></tr><tr><td>8</td><td>3GPP TS 23.060</td><td>General Packet Radio Service (GPRS); Service description</td></tr><tr><td>9</td><td>3GPP TR 25.993</td><td>Typical examples of Radio Access Bearers (RABs) and Radio Bearers (RBs) supported by Universal Terrestrial Radio Access (UTRA)</td></tr><tr><td>10</td><td>3GPP TS 34.108</td><td>Common test environments for User Equipment (UE); Conformance testing</td></tr><tr><td>11</td><td>3GPP TS 36.523-1</td><td>Evolved Universal Terrestrial Radio Access (E-UTRA) and Evolved Packet Core (EPC); User Equipment (UE) conformance specification; Part 1: Protocol conformance specification</td></tr><tr><td>12</td><td>ITU-T Recommendation H.264 (2005):</td><td>"Advanced video coding for generic audio-visual services" | ISO/IEC 14496-10:2005: "Information technology - Coding of audio-visual objects - Part 10: Advanced Video Coding".</td></tr><tr><td>13</td><td>IETF RFC 3840</td><td>Indicating User Agent Capabilities in the Session Initiation Protocol (SIP)</td></tr><tr><td>14</td><td>IETF RFC 3841</td><td>Caller Preferences for the Session Initiation Protocol (SIP)</td></tr><tr><td>15</td><td>ITU-T Recommendation H.265 (04/2013):</td><td>High efficiency video coding</td></tr><tr><td>16</td><td>IETF RFC 4796</td><td>The Session Description Protocol (SDP) Content Attribute</td></tr><tr><td>17</td><td>3GPP TS 24.173</td><td>IMS Multimedia telephony communication service and supplementary services; Stage 3</td></tr><tr><td>18</td><td>3GPP TS 24.610</td><td>Communication HOLD (HOLD) using IP Multimedia (IM) Core Network (CN) subsystem; Protocol specification</td></tr><tr><td>19</td><td>ITU-T Recommendation H.263 (01/2005)</td><td>Video coding for low bit rate communication</td></tr><tr><td>20</td><td>3GPP TS 24.237</td><td>IP Multimedia (IM) Core Network (CN) subsystem IP</td></tr><tr><td></td><td></td><td>Multimedia Subsystem (IMS) service continuity; Stage 3</td></tr><tr><td>21</td><td>3GPP TS 23.167</td><td>IP Multimedia Subsystem (IMS) emergency sessions</td></tr><tr><td>22</td><td>GSMA PRD TS.32</td><td>Technical Adaptation of Devices through Late Customisation</td></tr><tr><td>23</td><td>3GPP TS 24.275</td><td>Management Object (MO) for Basic Communication Part (BCP) of IMS Multimedia Telephony (MMTEL) communication service</td></tr></table>

# 2 IMS Feature Set

# 2.1 General

The IMS profile part lists the mandatory capabilities, which are required over the Gm and Ut reference points. 

# 2.2 Support of Generic IMS Functions

# 2.2.1 SIP Registration Procedures

In addition to the procedures in clause 2.2.1 of IR.92 [1], and for interoperability and forwardcompatibility reasons, the UE must indicate the capability to handle video calls by adding a “video” media feature tag to the Contact header field of the REGISTER request, as described in IETF RFC 3840 [13]. 

Note 1: Forking in the network is outside the scope of the present document. 

Note 2: The means to differentiate between a GSMA PRD IR.94 video call and another video service in MMTel is For Further Study (FFS). 

The home operator can configure the UE with Media_type_restriction_policy for non-roaming and for roaming cases as specified in Annex C.3. 

# 2.2.1a Addressing

In addition to the procedures in clause 2.2.3 of GSMA PRD IR.92 [1], if the local number type is not explicitly indicated by the user in outgoing video calls to either geo-local or homelocal numbers, then the UE must use the configuration parameter “Local number type for voice and video calls” as specified in Annex C.3 of GSMA PRD IR.92 [1] to determine the local number type. 

# 2.2.2 Call Establishment and Termination

In addition to procedures in IR.92 [1] clause 2.2.4, the UE and the network must be able to establish a video call directly during session establishment and by adding video to a voice session by sending Session Initiation Protocol (SIP) (re-)INVITE request with a Session Description Protocol (SDP) offer that contains both voice and video media descriptors. 

The UE must be able to accept an INVITE request without an SDP offer and must include an SDP offer in the first non-failure reliable response to an INVITE request without SDP offer. The SDP offer must contain all codecs (for audio only or for both audio and video) that the UE is currently able and willing to use. 

Note 1: How the UE determines to be able and willing to use audio only or both audio and video is out of scope of this document. 

To guide forking at the remote side, the UE must include a “video” media feature tag in the Accept-Contact header of an INVITE request for a video call, as described in IETF RFC 3840 [13] and RFC 3841 [14]. 

Note 2: Together with the ICSI value in a media feature tag as specified in section 2.2.4 of GSMA PRD IR.92 [1], will give preference for a conversational video and voice capable device in the forking algorithm. 

Note 3: The means to differentiate between an IR.94 video call and another video service in MMTel is FFS. 

The UE shall indicate the capability to handle video by including a “video” media feature tag in the Contact header of an INVITE request independent of if video media is part of the SDP offer or not. 

The UE shall indicate the capability to handle video by including a “video” media feature tag in the Contact header of any 18x or 200 response to an INVITE request independent of if video media is part of the SDP answer or not. 

The UE must be able to send SDP offer and answer with full duplex video media. 

An SDP answer may decline the video media by setting the port number of the video media descriptor to zero, accept the video media in full duplex mode by omitting SDP direction attribute or using the sendrecv SDP attribute, or accept the video media in simplex mode by using the send only or recvonly SDP attribute. 

If the UE receives an SDP offer with multiple video streams, and the UE can only handle a single video stream then: 

 The user may be given the possibility to choose which video stream to accept. 

If the user cannot be given the possibility to choose which video stream to accept, then the UE must accept or decline the main video stream and decline all other video streams. If the UE cannot determine which video stream in the SDP offer is the main video stream then it must consider the first video stream in the SDP offer that is supported by the UE as the main video stream. 

Note 4: A UE can provide information to the user on which video stream to accept by using information provided in an "i=" SDP line, if available, or by other means, and can determine the main video stream from an “a=content:main” attribute or by other means. The main video stream is the video stream taken from the main video source as described in IETF RFC 4796 [16]. 

The video stream in a video call may be changed between simplex or duplex mode, or made inactive, by sending a re-INVITE request with an SDP offer using the appropriate attribute in the video media descriptor (sendrecv, sendonly, recvonly or inactive). 

A video stream in a video call can be removed by sending a SIP re-INVITE request with an SDP offer where the port number of the video descriptor is set to zero. 

# 2.2.3 Early Media

The UE must be ready to receive SIP responses associated with multiple early dialogues, generated due to a forked request as specified in section 2.2.5 of GSMA PRD IR.92 [1]. The UE must support reception of voice and video media associated with one (1) early dialogue. 

# 2.2.4 SIP OPTIONS

As section 2.2.9 of GSMA PRD IR.92 [1] with the following addition: 

 A Contact header in a SIP OPTIONS request and a 200 OK response message to a SIP OPTIONS request must include a “video” media feature tag. 

# 2.3 Supplementary Services

# 2.3.1 General

The UE and the network must fulfil the requirements on supplementary services specified in section 2.3 of GSMA PRD IR.92 [1] with the additions in the following sub sections. 

# 2.3.2 Communication Hold

The UE and IMS core network must support the Communication Hold procedures as specified in section 2.3.1 of GSMA PRD IR.92 [1]. In addition, the UE shall request both the voice and the video media streams to be held or resumed using the procedures described in 3GPP TS 24.610 [18], section 4.5.2.1. The network shall only initiate the procedures for the provisioning of announcement to the held user or use the network option to reduce bandwidth described in 3GPP TS 24.610 [18] section 4.5.2.4, if both voice and video media streams are held. 

When restoring video media flow after a hold procedure, 3GPP TS 26.114 [6] section 14.3 must be followed. 

# 2.3.3 Ad-Hoc Multi Party Conference

The UE and IMS core network must support the procedures specified in section 2.3.3 of GSMA PRD IR.92 [1] with the following additions: 

The UE and IMS core network must support one audio and one video media stream for the conference session. 

A video conference is established by the conference creator UE with an SDP offer that contains both voice and video media descriptors in the INVITE to the conference focus, as described in Section 5.3.1.3.3 of 3GPP TS 24.147 [4]. 

A UE that is invited to the conference as described in Section 5.3.1.5.3 of 3GPP TS 24.147 [4] may participate in the conference as a voice only participant by using a SDP answer where the port number of the video descriptor is set to zero. 

A conference participant in an established video conference may request that its video connection to the conference focus is removed by sending a SIP re-INVITE request with an SDP offer where the port number of the video descriptor is set to zero. The video stream can be re-established by sending a new SIP re-INVITE request with an SDP offer where the port number of the video descriptor is set to a non-zero value. 

If the conference participant that established the video conference sends a SIP re-INVITE where the video is removed it is up to network policies if the conference shall be degraded to a voice only conference or if the video conference can continue with the conference originator participating only using voice. 

# 2.4 Call Set-up Considerations for Calls with Video Media

# 2.4.1 Integration of Resource Management and SIP

If a Guaranteed Bit Rate (GBR) bearer used for video fails to get established, or is lost midsession, then the network, based on its policies, has the option to either allow the session to continue as a voice only call, or terminate the SIP session that the GBR bearer is associated with according to the procedures in section 5.2.8 in TS 24.229 [5] (Proxy- Call Session Control Function (P-CSCF) must be informed about loss of bearer by the Policy and Charging Rules Function (PCRF)). 

Note 1: The network can handle loss of video on a GBR bearer in a video call in such a way that the session is allowed to continue although the video bearer was lost. The SIP session shall then be modified by the UE to a voice only session. 

If a Guaranteed Bit Rate (GBR) bearer used for the video media stream fails to get established, is lost mid-session, then the UE must, based on its preferences, modify, reject or terminate the SIP session that the media bearer is associated with, according to section 6.1.1 in 3GPP TS 24.229 [5]. 

If a Non-Guaranteed Bit Rate (non-GBR) bearer used for the video media stream fails to get established, is lost mid-session, or is not providing for a sufficient Quality of Service (QoS) level, then the UE may, based on its preferences, modify, reject or terminate the SIP session that the dedicated media bearer is associated with, according to section 6.1.1 in 3GPP TS 24.229 [5]. 

# 2.4.2 Video Media Considerations

The Session Description Protocol (SDP) offer/answer for video media must be formatted as specified in Section 6.2.3 of 3GPP TS 26.114 [6], along with the restrictions included in the present document. 

Coordination of Video Orientation (CVO) as specified in 3GPP Release 12 TS 26.114 [6] shall be supported with two (2) bits granularity by the UE and the entities in the IMS core network which terminate the user plane. The support for CVO shall be included in SDP offer and SDP answer as specified in section 6.2.3 of 3GPP Release 12 TS 26.114 [6]. 

Unless pre-configured otherwise by the home operator with the Default_EPS_bearer_context_usage_restriction_policy parameter as specified in Annex C.3, 

if a dedicated bearer for the media does not exist, the UE must consider itself not having local resources. If the UE has no local resources, the UE must not send media. See also section L.2.2.5.1B in 3GPP TS 24.229 [5]. 

NOTE: The existence of a dedicated bearer does not by itself grant the UE authority to send media. Other conditions need to be satisfied as well. 

# 2.4.3 SIP Precondition Considerations

The UE must support and use the SIP preconditions framework, as specified in 3GPP TS 24.229 [5] and in GSMA PRD IR.92 [1]. 

The network may disable the use of preconditions in the network; the means by which this takes place is outside the scope of this document. 

# 2.5 User-Agent and Server Headers

The UE must support the User-Agent and Server headers for SIP and the User-Agent header for HTTP as defined in GSMA PRD IR.92 [1]. 

# 3 IMS Media

# 3.1 General

This section endorses a set of media capabilities specified in 3GPP TS 26.114 [6]. The section describes the needed SDP support in UEs and in the IMS core network and it describes the necessary media capabilities both for UEs and for entities in the IMS core network that terminate the user plane. An example of an entity in the IMS core network that terminates the user plane is the Media Resource Function Processor (MRFP). 

# 3.2 Voice Media

The UE and the core network must follow the voice media requirements in section 3.2 of GSMA PRD IR.92 [1] and the requirements on DTMF events in section 3.3 of GSMA PRD IR.92 [1]. 

# 3.3 Video Media

# 3.3.1 Video Codec

The entities in the IMS core network that terminate the user plane must support ITU-T Recommendation H.264 [12] Constrained Baseline Profile (CBP) Level 1.2 as specified in 3GPP release 10 TS 26.114 [6] section 5.2.2. 

The UE must support ITU-T Recommendation H.264 [12] Constrained High Profile (CHP) Level 3.1 as specified in 3GPP release 13 TS 26.114 [6] section 5.2.2. 

For backward compatibility, the UE must also support ITU-T Recommendation H.264 [12] Constrained Baseline Profile (CBP) Level 3.1 as specified in 3GPP release 10 TS 26.114 [6] section 5.2.2, and when H.264 [12] (Advanced Video Coding (AVC)) CHP Level 3.1 is offered, then H.264 [12] CBP Level 3.1 must also be offered. 

Note 1: Support in the UE and the entities in the IMS core network that terminate the user plane for H.265 [15] (High Efficiency Video Coding (HEVC)) Main Profile, Main Tier, Level 3.1, as specified in 3GPP release 12 TS 26.114 [6] section 5.2.2, is recommended to accommodate future needs for operators to further optimise the bitrate/quality trade-off for video in and between operator networks. 

The support in the UE of ITU-T Recommendation H.263 [19] Profile 0 Level 45 as specified in 3GPP release 8 TS 26.114 [6], section 5.2.2, is not required. 

Note 2: For codec Levels allowing a very high maximum bit rate (like Level 3.1 for H.264 [12] or H.265 [15]) it is expected that the codec is used with a maximum bit rate much lower than the maximum bit rate allowed by the Level and operated with rate adaptation to adjust the bitrate to network transmission capabilities (rate adaptation mechanisms are described in clause 3.3.3). 

When sending the currently active H.264 [12] parameter set (Sequence Parameter Sets (SPS) and Picture Parameter Sets (PPS)) in the RTP media stream, the UE and the entities in the network terminating the media plane must repeat the parameter set at multiple occasions with appropriate spacing with regards to the channel loss characteristics. 

Note 3: The UE may implement different algorithms on how to repeat the parameter set in the RTP media. Since packet loss is expected to be higher at the start of transmission, it is recommended that the parameters are repeated in a progressively slowing rate. 

Note 4: SPS and PPS are two types of parameter set structures (syntax structures), used in the H.264 [12] coded video, as described in Section 3, 7.3, and 7.4 of ITU-T Recommendation H.264 [12]. 

Change of video resolution mid-stream by transmission of new parameter sets in the RTP media stream must be supported, as long as those parameter sets conforms to the media stream configuration negotiated in SDP. 

Note 5: Change of video resolution can occur if an MRFP switches in for example a H.264 [12] CBP Level 1.1 source to a UE supporting H.264 [12] CBP Level 1.2. The MRFP may need to trigger the sending of the parameter set by sending a RTCP Full Intra Request (FIR) message to the new source. 

When receiving a Full Intra Request (FIR) for a video media stream, the UE and the entities terminating the media plane in the network must send the currently active parameter sets followed by a decoder refresh point. 

Note 6: A decoder refresh point can be sent using an Instantaneous Decoding Refresh (IDR) picture in H.264 [12] or an Intra Random Access Point (IRAP) picture having nal_unit_type equal to IDR_N_LP in H.265/HEVC [15]. 

# 3.3.2 RTP Profile and Data Transport

The UE and the entities terminating the media plane in the network supporting IMS conversational video services must offer the AVPF RTP profile in initial SDP offers of video media, as specified in Section 6.2.1a of 3GPP TS 26.114 [6]. 

If the initial SDP offer does not use the SDP Capability Negotiation and if the UE receives either: 

A response with an SDP answer where the video media component has been rejected and the Contact header field in the response does not contain a g.3gpp.icsiref feature tag indicating IMS Multimedia Telephony Service; or 

A SIP 488 or 606 failure response with an SDP body indicating that only AVP is supported for video media. 

Then the UE shall send a new SDP offer with AVP as transport for video as described in Section 6.2.1a.2 of 3GPP TS 26.114 [6]. 

Note 1: If an SDP answer, indicating that only the voice media was accepted is received in a reliable SIP 183 session progress response, the new SDP offer shall be sent in the associated PRACK request, or in a subsequent UPDATE request. If an SDP answer, indicating that only the voice media was accepted is received in a 200 OK response, the new SDP offer shall be sent in a subsequent re-INVITE request. 

Note 2: A UE supporting IMS Multimedia Telephony Service supports AVPF for video as described in section 6.2.3 of 3GPP TS 26.114 [6]. The rejection of the video media from such a device is due to the device not supporting video, the remote user rejecting the video media or network policy prohibits video. 

Note 3: The use of SDP Capability Negotiation to offer the AVPF profile for video is optional in 3GPP. When an IR.94 device not supporting SDP CapNeg receives an offer using SDP CapNeg offering AVPF for video then the AVP offered in the media line will be used for the video media. This may cause a bad service experience for example when participating in a video conference or when an Inter-RAT handover occurs. The UE can upgrade the video session to use AVPF and rtcp-fb messages to ensure a good user experience. 

3GPP TS 26.114 [6] (section 7.2) applies both for UE and entities in the IMS core network that terminates the user plane for video. 

The specification of data transport for voice media in section 3.2.3 in GSMA PRD IR.92 [1] applies also for video media. 

The UE and the entities terminating the media plane in the network supporting IMS conversational video services are recommended to support RTP retransmission for video media, as specified in Sections 6.2.3.5, 7.4.6, and 9.3 of 3GPP Rel. 13 TS 26.114 [6]. If RTP retransmission is supported, the UE and the entities terminating the media plane in the network: 

Must keep also the RTP retransmission payload type in SDP answer, if it was included in the corresponding SDP offer for the accepted video media. 

Must set the RTP retransmission “rtx-time” SDP parameter to 800 in generated SDP offers and answers if RTP retransmission payload type is included in the SDP, but must accept the reception of other values and be able to handle them. 

# 3.3.3 RTCP Usage

The UE and the entities terminating the media plane in the network must support the use of RTCP video media in the same way as defined in section 3.2.4 of GSMA PRD IR.92 [1] for voice media with the following additions: 

Reduced size RTCP packets may be used if agreed in SDP offer/answer as specified in section 7.3.6 of 3GPP TS 26.114 [6]. Otherwise, RTCP compound packet format must be used. 

The UE and the entities in the IMS core network that terminate the user plane must support the use of the Full Intra Request (FIR) of Codec-Control Messages (CCM) as specified in section 7.3.3 of 3GPP TS 26.114 [6]. 

Note 1: The FIR message is used to request the video codec to send a decoder refresh point as soon as possible. This is needed for example when a video MRF switches the video signal to be sent to conference participants. 

For interoperability and forward-compatibility reasons, the UE must support the reception of the Temporary Maximum Media Bit-rate Request (TMMBR) from the remote end and respond with the Temporary Maximum Media Bit-rate Notification (TMMBN) as described in section 10.3 of 3GPP TS 26.114 [6]. 

The UE and the entities in the IMS core network that terminates the user plane must support at least one adaptation trigger as specified in section 10.3.3 of 3GPP Rel. 12 TS 26.114 [6]. The UE and the entities in the IMS core network that terminates the user plane must detect whether the bitrate needs to be reduced or can be increased and it must be able to send a corresponding TMMBR message as specified in section 10.3.6 and 10.3.7 of 3GPP Rel. 12 TS 26.114 [6]. 

The UE and the entities in the IMS core network that terminate the user plane must react to a received TMMBR message by responding with a TMMBN message and either reducing the bitrate as described in 10.3.4 of 3GPP Rel. 12 TS 26.114 [6] or increasing the bitrate as described in 10.3.5 of 3GPP Rel. 12 TS 26.114 [6]. 

The UE must support and use the sending and reception of the AVPF messages NACK and Picture Loss Indication (PLI) as described in section 9.3 of 3GPP Rel. 13 TS 26.114 [6]. The entities in the IMS core network that terminate the user plane must support reception of the AVPF messages NACK and Picture Loss Indication (PLI) but are not required to take any action. For the case where no action is taken, the message must be forwarded. 

Note 2: If core network nodes terminate AVPF messages without action rather than forward the messages, it prevents other entities (including the remote UE) to be aware of the messages and thus take any necessary corrective action. 

The UE and the entities in the IMS core network that terminate the user plane and that support RTP retransmission must also support the use of NACK as input to RTP retransmission, as described in section 9.3 of 3GPP Rel. 13 TS 26.114 [6]. 

# 3.3.4 RTP Payload Format Considerations for Video

3GPP release 12 TS 26.114 [6] (section 7.4.3) applies both for UE and entities in the IMS core network that terminate the user plane. 

If use of CVO has been accepted in SDP negotiation as specified in section 2.4.2, then CVO with the negotiated granularity shall be used by the UE and the entities in the IMS core network that terminate the user plane as specified in section 7.4.5 of 3GPP Release 12 TS 26.114 [6]. 

# 4 Radio and Packet Core Feature Set for Video

# 4.1 General

The UE and the network that supports conversational video service over LTE access must fulfil the requirements on radio and packet core feature set specified in section 4 of GSMA PRD IR.92 [1] with the additions in the following sub sections. 

# 4.2 Bearer Considerations for Video

# 4.2.1 E-UTRAN

For an IMS session request for a video call (originating or terminating) in E-UTRAN, one dedicated bearer resource for voice as specified in IR.92 [1] and another dedicated bearer resource for video must be created by authorizing the flows utilizing dynamic PCC (Policy and Charging Control). The network must initiate the creation of dedicated bearer resources to transport the voice and the video media. 

The dedicated bearer for Conversational Video stream may be a GBR or a non-GBR bearer. If a GBR bearer is used it must utilize the standardized QCI value of two (2) and have the associated characteristics as specified in 3GPP TS 23.203 [3]. 

For IMS session termination of a session using conversational media, the dedicated bearer resources must be deleted by withdrawing the authorization of the flows. The network must initiate the deletion of the bearer resources. 

# 4.3 LTE Radio Capabilities

The UE must be able to use two UM Radio Data Bearers for two GBR bearers that may be used for a conversational video call. The UE must therefore support feature group indicator 20 indicating support for the following combination of radio bearers for conversational video service (see Annex B in 3GPP TS 36.331 [7]): 

$$
S R B 1 + S R B 2 + 5 \times A M D R B + 3 \times U M D R B
$$

If the network uses an UM DRB for the video media stream, it must support a radio bearer combination with at least: 

$$
S R B 1 + S R B 2 + 2 \times A M D R B + 2 \times U M D R B
$$

This corresponds to Radio Bearer combination identifier 5 in table 12.1 in 3GPP TS 36.523-1 [11]. 

In addition to the bearer usage specified in section 4.2.1 of GSMA PRD IR.92 [1], one DRB is used for an EPS bearer for video. 

# 5 Common Functionalities

# 5.1 Data Off and Services Availability

The UE must and the network can support the procedures specified in section 5.5 of the GSMA PRD IR.92 [1] with the following addition: 

If Conversational Video Service is not in the list of 3GPP PS Data Off Exempt Services or Conversational Video Service in the list of 3GPP PS Data Off Exempt Service is configured not to be a 3GPP PS Data Off Exempt Service as in Table C.3.1, and if 3GPP PS Data Off is active, the use of Conversational Video Service is disabled. 

# 5.2 Capability Discovery

The UE and the network must support the requirements of section 5.7 in GSMA PRD IR.92 [1] with the following addition: 

Capability Discovery is applicable for the following service: Conversational video. 

# Annex A Complementing IMS with CS

# A.1 General

The UE and the network may support the deployment scenario described in PRD IR.92 [1] Annex A. 

# A.2 SR-VCC

If a session transfer procedure as described in section A.3 of PRD IR.92 [1] is executed for the speech component of an active conversational Video session, and if the UE retains the Gm reference point upon PS handover as described in Section 12.2.3 of 3GPP TS 24.237 [20], then in addition to removal of the speech media component from the session on Gm, the UE must also remove the video media component from this session, that is the video media from the video call is discontinued after the session transfer. 

# Annex B Features needed in certain regions

# B.1 General

This annex describes features that operators need to support in certain regions due to local regulatory requirements. 

# B.2 Video media in emergency service

To support conversational video service as defined in section 1.1 of this document for emergency service, the specification of emergency service in GSMA PRD IR.92 [1] is extended as follows: 

In regions where the capability is required, UEs and network deployments must support IMS emergency services using video media as well. The UE and the network must support the Release 11 IMS emergency services as specified in TS 23.167 [21], chapter 6 and Annex H. 

Annex A also applies for video media in emergency service. 

The UE must support Real-Time Text in emergency service, in addition to support of speech in emergency sessions as in GSMA PRD IR.92 [1] and support of video in emergency sessions as in this subclause. 

# Annex C MNO Provisioning and Late Customization

# C.1 General

This annex describes the capabilities to support MNO provisioning and late customization as defined in Annex C in GSMA PRD IR.92 [1]. 

# C.2 Configuration Methods

See Annex C.2 in GSMA PRD IR.92 [1]. 

# C.3 Configuration Parameters

Table C.3.1 contains the configuration parameters with their default values that must be supported by the UE, in addition to those defined in GSMA PRD IR.92 [1]. The default values shown in Table C.3.1 for “Voice and/or Video over LTE allowed” and “Voice and/or Video over LTE allowed when roaming” must be used instead of the corresponding default values defined in GSMA PRD IR.92 [1]. 

The UE must use the default value for each parameter in Table C.3.1 unless configured differently by any of the methods as described in section C.2. 


Note: The parameters in Table C.3.1 are a subset of parameters in section 3.8 of GSMA PRD TS.32 [22].


<table><tr><td>Parameter</td><td>Default value</td><td>Defined in</td><td>See also clause</td></tr><tr><td>Media_type_restriction_policy(Voice and/or Video over LTE allowed)</td><td>Voice and video allowed</td><td>Section 5.43 of 3GPP Release 14 TS 24.167 [21] (interior node [/X&gt;/Media_type_restriction_policy) and 3GPP Release 14 TS 24.229 [5]</td><td>2.2.1</td></tr><tr><td>Media_type_restriction_policy(Voice and/or Video over LTE allowed when roaming)</td><td>Voice and video prohibited</td><td>Section 5.43 of 3GPP Release 14 TS 24.167 [21] (interior node [/X&gt;/Media_type_restriction_policy) and 3GPP Release 14 TS 24.229 [5]</td><td>2.2.1</td></tr><tr><td>Default_EPS_bearer_context_USAGE_restriction_policy(Voice and/or Video Media on default (QCI=5) bearer)</td><td>Prohibited</td><td>Section 5.49 of 3GPP Release 14 TS 24.167 [21] (interior node [/X&gt;/Default_EPS_bearer_context_USAGE_restriction_policy) and 3GPP Release 14 TS 24.229 [5]</td><td>2.4.2</td></tr><tr><td>MMTEL(video_exempt</td><td>0 – Indicates that the MMTEL video is not a 3GPP PS data off exempt</td><td>Section 5.8 of 3GPP Release 14 TS 24.275 [23] (/[X]/3GPP_PS_data_off/MMTEL_video_exempt)</td><td>5.1</td></tr></table>

<table><tr><td>Parameter</td><td>Default value</td><td>Defined in</td><td>See also clause</td></tr><tr><td></td><td>service</td><td></td><td></td></tr></table>


Table C.3.1 Configuration parameters and their default values


# Annex D Document Management

# D.1 Document History

<table><tr><td>Version</td><td>Date</td><td>Brief Description of Change</td><td>Approval Authority</td><td>Editor / Company</td></tr><tr><td>0.1</td><td></td><td>First draft</td><td>RILTE/REG</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>0.2</td><td></td><td>Input to RILTE 18</td><td>RILTE/REG</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>0.3</td><td></td><td>Input to RILTE 19</td><td>RILTE/REG</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>0.4</td><td></td><td>H.263 removed as mandatory codec</td><td>RILTE/REG</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>0.5</td><td></td><td>Change of document template.</td><td>RILTE/REG</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>0.6</td><td></td><td>Output from RILTE 20</td><td>RILTE/REG#61 EMC</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>1.0</td><td>December 2011</td><td>Submitted to DAG and EMC for approval, final approval date 28 December 2011</td><td>EMC</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>2.0</td><td>30/05/2012</td><td>CR 001 to CR 004</td><td>RILTE/REG#62 EMC</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>3.0</td><td>4/07/2012</td><td>CR 005 to CR 008</td><td>RILTE/REG email approval PSMC#104</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>4.0</td><td>23/11/2012</td><td>CR 009, CR 010, CR 011, CR 013</td><td>RILTE/REG email approval PSMC#108</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>5.0</td><td>22/02/2013</td><td>CR1001</td><td>PSMC #1092</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>6.0</td><td>18/04/2013</td><td>CR1002,CR1003,CR1004,CR1005</td><td>PSMC#112</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>6.1</td><td>11/09/2013</td><td>CR1006</td><td></td><td>Lennart Norell/ Ericsson</td></tr><tr><td>7.0</td><td>16/04/2014</td><td>CR1007, T8</td><td>IREG#66</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>8.0</td><td>17/11/2014</td><td>CR1008</td><td>IREG#67</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>9.0</td><td>20/02/2015</td><td>CR1009</td><td>NG#1</td><td>Lennart Norell/ Ericsson</td></tr><tr><td>10.0</td><td>22/10/2015</td><td>CR1010</td><td>RILTE#48</td><td>Bo Burman/ Ericsson</td></tr><tr><td>11.0</td><td>26/05/2016</td><td>CR1011, CR1012, CR1013, CR1014, CR1015, CR1016, CR1017, CR1018, CR1019, CR1020</td><td>RILTE#52</td><td>Bo Burman/ Ericsson</td></tr><tr><td>12.0</td><td>12/06/2017</td><td>CR1021, CR1022, CR1023, CR1024, CR1025</td><td>NG#5</td><td>Bo Burman/ Ericsson</td></tr><tr><td>13.0</td><td>21/06/2018</td><td>CR1026, CR1027</td><td>NG#8</td><td>Bo Burman/ Ericsson</td></tr><tr><td>14.0</td><td>17/04/2019</td><td>CR1028, CR1029, CR1030, CR1031, CR1032, CR1033</td><td>NG#9</td><td>Bo Burman/ Ericsson</td></tr></table>

# Other Information

<table><tr><td>Type</td><td>Description</td></tr><tr><td>Document Owner</td><td>NG RILTE</td></tr><tr><td>Editor / Company</td><td>Bo Burman / Ericsson</td></tr></table>

It is our intention to provide a quality product for your use. If you find any errors or omissions, please contact us with your comments. You may notify us at prd@gsma.com 

Your comments or suggestions & questions are always welcome. 