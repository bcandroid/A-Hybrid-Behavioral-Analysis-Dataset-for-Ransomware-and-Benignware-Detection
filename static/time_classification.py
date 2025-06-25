import os
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.utils import shuffle
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, mean_absolute_error, mean_absolute_percentage_error,
                             matthews_corrcoef, balanced_accuracy_score, cohen_kappa_score, log_loss,
                             confusion_matrix, r2_score)
import r2pipe

def main():
    # File paths
    out1 = '/home/remnux/Downloads/input/count.csv'
    out2 = '/home/remnux/Downloads/input/tf.csv'

    # Load data
    x1, y1 = load_data(out1)
    x0 = x1[y1 == 0]
    y0 = y1[y1 == 0]
    x1_class = x1[y1 == 1]
    y1_class = y1[y1 == 1]

    # Split data
    x_remaining, x0_sample, y_remaining, y0_sample = train_test_split(
        x0, y0, test_size=0.15, random_state=42, shuffle=True
    )

    # Combine training data
    x_train = pd.DataFrame(np.vstack((x_remaining, x1_class)))
    y_train = pd.Series(np.hstack((y_remaining, y1_class)))

    # Test data
    x_test1 = x0_sample
    y_test = y0_sample

    # Scale data
    scaler = StandardScaler()
    x_train1 = scaler.fit_transform(x_train)
    

    x_train1, y_train = shuffle(x_train1, y_train, random_state=42)

    rf_model1 = RandomForestClassifier(n_estimators=150, max_depth=20, random_state=42)
    rf_model1.fit(x_train1, y_train)

    # Analyze new data
    start_time = time.time()
    path = '/home/remnux/Downloads/input/mix'
    opcoded, c = initial_analysis(path)
    
    # Use column names from the CSV file for vocabulary
    column_names = get_col(out1)  # Corrected to get column names properly
    vectorizer = CountVectorizer(vocabulary=column_names, tokenizer=lambda x: x.split())
    Xop = vectorizer.fit_transform(opcoded)
    
    # Combine opcode features with existing test data
    x_test_combined = pd.DataFrame(np.vstack((Xop.toarray(), x_test1)))
    x_test_combined = scaler.transform(x_test_combined)
    te = [1] * c
    test_labels = pd.Series(np.hstack((te, y_test)))
    
    # Shuffle test data
    x_shuff, y_shuff = shuffle(x_test_combined, test_labels, random_state=42)
    
    # Make predictions
    y_pred_test = rf_model1.predict(x_shuff)
    y_pred_proba = rf_model1.predict_proba(x_shuff)
    
    elapsed_time = time.time() - start_time
    df = pd.DataFrame(Xop.toarray(), columns=vectorizer.get_feature_names_out())
    df.to_csv("opcodelar_count_vector.csv", index=False)
    
    average_time = elapsed_time / c
    print(f"Time taken: {elapsed_time:.2f} seconds")
    print(f"Average time taken: {average_time:.2f} seconds")

    # Metrics
    accuracy = accuracy_score(y_shuff, y_pred_test)
    precision = precision_score(y_shuff, y_pred_test)
    recall = recall_score(y_shuff, y_pred_test)
    f1 = f1_score(y_shuff, y_pred_test)
    roc_auc = roc_auc_score(y_shuff, y_pred_proba[:, 1])
    cm = confusion_matrix(y_shuff, y_pred_test)
    specificity = cm[0, 0] / (cm[0, 0] + cm[0, 1])
    g_mean = np.sqrt(recall * specificity)

    # Print results
    print("\nEvaluation Results:")
    print(f"Accuracy: {accuracy:.2f}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall (Sensitivity): {recall:.2f}")
    print(f"Specificity: {specificity:.2f}")
    print(f"G-Mean: {g_mean:.2f}")
    print(f"F1-Score: {f1:.2f}")
    print(f"ROC-AUC: {roc_auc:.2f}")
    print("\nConfusion Matrix:")
    print(cm)

def load_data(file_path):
    data = pd.read_csv(file_path)
    x = data.iloc[:, :-1].values
    y = data.iloc[:, -1].values
    return x, y

def get_col(file_path):

    data = pd.read_csv(file_path)
    return data.columns.tolist()[:-1]  # Exclude the last column if it's the label

def process_file(file_name, path):
    absolute_file_name = os.path.join(path, file_name)
    try:
        print(f"Analyzing: {file_name}")
        malware = r2pipe.open(absolute_file_name)
        malware.cmd("e asm.arch = x86")
        malware.cmd("e asm.bits = 32")
        malware.cmd("e cfg.bigendian=false")
        malware.cmd("e bin.relocs.apply=true")
        malware.cmd("e bin.cache=true")
        malware.cmd("e anal.nopskip=false")
        malware.cmd("e anal.hasnext = true")
        malware.cmd("e anal.bb.maxsize=2097152")
        malware.cmd("aaaa")
        pdf_output = malware.cmd("pif @@f ~[0]").splitlines()
        if not pdf_output:
            print(f"No opcodes extracted for {file_name}")
            return None
        opcodes = ' '.join(pdf_output)
        return opcodes
    except Exception as e:
        print(f"Error processing file {file_name}: {e}")
        return None

def initial_analysis(path):
    file_names = [f for f in os.listdir(path)]
    data = []
    for file_name in file_names:
        result = process_file(file_name, path)
        if result:
            data.append(result)
    count = len(data)
    return data, count

if __name__ == "__main__":
    main()
