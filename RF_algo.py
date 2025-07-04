import time
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, r2_score, mean_absolute_error, mean_absolute_percentage_error,
    matthews_corrcoef, balanced_accuracy_score, cohen_kappa_score, log_loss
)
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import matplotlib.pyplot as plt
import seaborn as sns

# CSV Dosyası Yükleme
filename = r'C:\Users\....\mix.csv'



# Veriyi Yükleme
df = pd.read_csv(filename)
file_names = df['filename'].values
# Veri ve Etiket Ayırma
def load_data(data):
    x = data.iloc[:, 1:-1].values
    y = data.iloc[:, -1].values
    return x, y

x1, y1 = load_data(df)
print(x1.shape)
print(y1.shape)
print(df.shape)
# Label Encoding (Metinsel etiketleri sayıya çevirme)
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y1)

# Veriyi Ölçeklendirme
scaler = MinMaxScaler(feature_range=(0, 1))
x_scaled = scaler.fit_transform(x1)

# StratifiedKFold ile Çapraz Doğrulama
#cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
start_time = time.perf_counter()
rf_model = RandomForestClassifier(n_estimators=150, max_depth=20, random_state=42)

# Cross-validation skorlarını hesapla
#cv_scores = cross_val_score(rf_model, x_scaled, y_encoded, cv=cv, scoring='f1')

#print(f"Cross-Validation F1-Scores: {cv_scores}")
#print(f"Ortalama F1-Score: {cv_scores.mean():.2f}")

# Eğitim ve Test Verisine Ayırma
x_train1, x_test1, y_train1, y_test1, train_file_names, test_file_names = train_test_split(
    x_scaled, y_encoded, file_names, test_size=0.2, random_state=42, shuffle=True, stratify=y_encoded
)

print(f"Length of x_scaled: {len(x_scaled)}")
print(f"Length of y_encoded: {len(y_encoded)}")
print(f"Length of file_names: {len(file_names)}")

# Modeli Eğitme
rf_model.fit(x_train1, y_train1)
end_time = time.perf_counter()
elapsed_time = end_time - start_time
print(f"Eğitim çalışma süresi: {elapsed_time:.2f} saniye")
# Tahmin
start_time = time.perf_counter()
y_pred_test = rf_model.predict(x_test1)

y_pred_proba = rf_model.predict_proba(x_test1)
end_time = time.perf_counter()
elapsed_time = end_time - start_time
print(f"Tahmin çalışma süresi: {elapsed_time:.2f} saniye")
# Metrik Hesaplama
accuracy = accuracy_score(y_test1, y_pred_test)
precision = precision_score(y_test1, y_pred_test)
recall = recall_score(y_test1, y_pred_test)
f1 = f1_score(y_test1, y_pred_test)
roc_auc = roc_auc_score(y_test1, y_pred_proba[:, 1])
r2 = r2_score(y_test1, y_pred_test)
mae = mean_absolute_error(y_test1, y_pred_test)
mape = mean_absolute_percentage_error(y_test1, y_pred_test)
mcc = matthews_corrcoef(y_test1, y_pred_test)
balanced_acc = balanced_accuracy_score(y_test1, y_pred_test)
cohen_kappa = cohen_kappa_score(y_test1, y_pred_test)
log_loss_value = log_loss(y_test1, y_pred_proba)

# Confusion Matrix
cm = confusion_matrix(y_test1, y_pred_test)
specificity = cm[0, 0] / (cm[0, 0] + cm[0, 1])
sensitivity = recall
g_mean = np.sqrt(sensitivity * specificity)

# Confusion Matrix Görselleştirme
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
plt.xlabel('Predicted')
plt.ylabel('True')
plt.title('Confusion Matrix')
plt.show()

# Değerlendirme Sonuçları
print("\nEvaluation Results:")
print(f"Accuracy: {accuracy:.2f}")
print(f"Precision: {precision:.2f}")
print(f"Recall (Sensitivity): {recall:.2f}")
print(f"Specificity: {specificity:.2f}")
print(f"G-Mean: {g_mean:.2f}")
print(f"F1-Score: {f1:.2f}")
print(f"ROC-AUC: {roc_auc:.2f}")
print(f"Balanced Accuracy: {balanced_acc:.2f}")
print(f"Log Loss: {log_loss_value:.2f}")
print(f"Mean Absolute Error (MAE): {mae:.2f}")
print(f"Matthews Correlation Coefficient (MCC): {mcc:.2f}")
print(f"Cohen's Kappa: {cohen_kappa:.2f}")

print("\nConfusion Matrix:")
print(cm)

# Class-Specific Accuracy
correct_class_0 = cm[0, 0] / cm[0].sum() * 100
correct_class_1 = cm[1, 1] / cm[1].sum() * 100

print(f"\nClass 0 Correctly Predicted: {correct_class_0:.2f}%")
print(f"Class 1 Correctly Predicted: {correct_class_1:.2f}%")


# Eğitim ve test setindeki sınıf dağılımını kontrol etme
unique, counts = np.unique(y_train1, return_counts=True)
print(f"Eğitim verisi sınıf dağılımı: {dict(zip(unique, counts))}")

unique, counts = np.unique(y_test1, return_counts=True)
print(f"Test verisi sınıf dağılımı: {dict(zip(unique, counts))}")

# Tahmin olasılıklarını histogram olarak görselleştirme
plt.figure(figsize=(10, 5))
plt.hist(y_pred_proba[:, 1], bins=50, alpha=0.7, label="Pozitif (1) Olasılıkları")
plt.hist(y_pred_proba[:, 0], bins=50, alpha=0.7, label="Negatif (0) Olasılıkları")
plt.xlabel("Tahmin Olasılığı")
plt.ylabel("Örnek Sayısı")
plt.title("Modelin Sınıf Tahmin Olasılıkları Dağılımı")
plt.legend()
plt.show()

# Eşik değeri ile tahmin ayarlama
# threshold = 0.6  
# y_pred_adjusted = (y_pred_proba[:, 1] >= threshold).astype(int)

# Yeni metrikleri hesaplama
# precision_adj = precision_score(y_test1, y_pred_adjusted)
# recall_adj = recall_score(y_test1, y_pred_adjusted)
# f1_adj = f1_score(y_test1, y_pred_adjusted)

# print(f"Yeni Precision: {precision_adj:.2f}")
# print(f"Yeni Recall: {recall_adj:.2f}")
# print(f"Yeni F1-Score: {f1_adj:.2f}")

misclassified_indices = np.where((y_test1 == 0) & (y_pred_test == 1))[0]

# Bu indekslerdeki file_name değerlerini almak (test_file_names sırasını doğru kullanıyoruz)
misclassified_file_names = test_file_names[misclassified_indices]

# file_name'leri bir metin dosyasına yazma
with open('misclassified_file_namesfiltered.txt', 'w') as f:
    for name in misclassified_file_names:
        f.write(name + '\n')

print("Misclassified file names (y=0, but predicted as 1) have been written to 'misclassified_file_names.txt'")
