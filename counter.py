import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer

file_name = r'C:\Users\bus_c\Desktop\output\a\opcodes_ou.csv'
file_path_to_process = r'C:\Users\bus_c\Desktop\output\a\opcodes_output.csv'

df_to_process = pd.read_csv(file_path_to_process, header=0, names=['file_name', 'content', 'yes'])
texts = df_to_process['content'].tolist()

count_vectorizer = CountVectorizer()
count_matrix = count_vectorizer.fit_transform(texts)

count_df = pd.DataFrame(count_matrix.toarray(), columns=count_vectorizer.get_feature_names_out())

# file_name ve yes sütunlarını ekle
count_df.insert(0, 'file_name', df_to_process['file_name'])
count_df['yes'] = df_to_process['yes']

# CSV dosyasına kaydet
count_df.to_csv(file_name, index=False)

print(count_df.shape)
