This study presents the **RansomTrack** dataset, developed through a hybrid analysis pipeline that integrates both static and dynamic inspection of Windows-based 32-bit executable files. Static features were extracted using disassembly techniques via Radare2, while dynamic behavioral features—including API calls and memory page protection changes—were captured in real time using the Frida instrumentation toolkit. The dataset comprises a total of 1002 static opcode-based features and 5024 dynamic features, derived from the analysis of 1205 benignware and 1205 ransomware samples.

The dataset includes filenames and corresponding samples listed in yes_0_filenames[1].csv (benignware list) and yes_1_filenames[1].csv (ransomware list), and selected ransomware binaries can be automatically retrieved from MalwareBazaar by executing the provided download_with_csv.py script.

Data Sources
Ransomware Samples:

1-Abuse.ch, “MalwareBazaar – A repository of malware samples,” 2025. [Online]. Available: \url{https://bazaar.abuse.ch/}

2-C. C. Moreira, D. C. Moreira, and C. S. de Sales Jr., “Improving ransomware detection based on portable executable header using Xception convolutional neural network,” Computers & Security, vol. 130, p. 103265, Jul. 2023. [Online]. Available: \url{https://doi.org/10.1016/j.cose.2023.103265}

Benignware Samples:

1-C. C. Moreira, D. C. Moreira, and C. S. de Sales Jr., ibid.

2-Bormaa, “Benign-NET: Benign Windows executables dataset,” GitHub, 2022. [Online]. Available: \url{https://github.com/bormaa/Benign-NET}

3-A. Iosifache, “DikeDataset – Benign sample files,” GitHub, 2023. [Online]. Available: \url{https://github.com/iosifache/DikeDataset/tree/main/files/benign}

Portions of the dynamic analysis workflow were adapted with reference to the publicly available repository MalwareMuncher, which provides Frida-based instrumentation scripts for malware behavior tracing.
1-fr0gger, “MalwareMuncher: Frida-based instrumentation framework for malware dynamic analysis,” GitHub, 2023. [Online]. Available: \url{https://github.com/fr0gger/MalwareMuncher}


**Researchers wishing to utilize the RansomTrack dataset are kindly requested to cite the following reference:**

**B. Çalışkan, İ. Gülataş, H. H. Kilinc, and A. H. Zaim, “The Recent Trends in Ransomware Detection and Behaviour Analysis,” in _Proc. 17th Int. Conf. Security of Information and Networks (SIN)_, Sydney, Australia, Dec. 2024, doi: [10.1109/SIN63213.2024.10871663](https://doi.org/10.1109/SIN63213.2024.10871663).**


![78 drawio (2)](https://github.com/user-attachments/assets/d4f4e630-7cff-45c3-930d-7a623772ba1e)
