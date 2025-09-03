import src.feature_extraction.classifier_features as classifier_features
import src.feature_extraction.anomaly_detector_features as anomaly_features
import streamlit as st
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np
import sklearn

st.title("PCAP Anomaly Detection Dashboard")

# File uploader for PCAP file
uploaded_file = st.file_uploader("Upload PCAP File", type=["pcap", "pcapng"])
if uploaded_file is not None:
    # Ensure the data/raw directory exists
    os.makedirs("data/raw", exist_ok=True)

    # Save the uploaded file inside data/raw
    pcap_path = os.path.join("data", "raw", uploaded_file.name)
    with open(pcap_path, "wb") as f:
        f.write(uploaded_file.getvalue())
    
    st.success(f"File '{uploaded_file.name}' uploaded successfully to data/raw/")

    try:
        os.makedirs("data/raw", exist_ok=True)

        anomaly_features.extract_flow_features(pcap_path,"data/processed/anomaly.csv")

        features_df = pd.read_csv("data/processed/anomaly.csv")

        st.success(f"Features extracted and saved to data/processed/anomaly.csv")
    except Exception as e:
        st.error(f"Error extracting features: {e}")
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
        st.stop()

    model_path = "src/models/isolation_forest.pkl"
    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            predictions = model.predict(features_df)
            features_df['Anomaly'] = predictions  # -1 for anomaly, 1 for normal
            anomaly_count = (predictions == -1).sum()
            total_flows = len(predictions)
            
            st.subheader("Anomaly Detection Results")
            st.write(f"Total flows analyzed: {total_flows}")
            st.write(f"Detected anomalies: {anomaly_count}")
            st.write(f"Anomaly rate: {anomaly_count / total_flows * 100:.2f}%")
            
            # Display the DataFrame with predictions
            st.dataframe(features_df)
        except Exception as e:
            st.error(f"Error loading or predicting with model: {e}")
            os.remove(pcap_path)
            st.stop()
    else:
        st.error("Model file 'anomaly.pkl' not found!")
        os.remove(pcap_path)
        st.stop()

    st.subheader("Visualizations")
    
    # Visualization 1: Histogram of Flow Duration
    fig1, ax1 = plt.subplots()
    ax1.hist(features_df['Flow Duration'], bins=50, color='skyblue', alpha=0.7)
    ax1.set_title("Histogram of Flow Duration")
    ax1.set_xlabel("Flow Duration (seconds)")
    ax1.set_ylabel("Frequency")
    st.pyplot(fig1)
    
    # Visualization 2: Scatter Plot of Flow Bytes/s vs Packet Length Mean
    fig2, ax2 = plt.subplots()
    scatter = ax2.scatter(
        features_df['Flow Bytes/s'],
        features_df['Packet Length Mean'],
        c=features_df['Anomaly'],
        cmap='coolwarm',
        alpha=0.6
    )
    ax2.set_title("Flow Bytes/s vs Packet Length Mean")
    ax2.set_xlabel("Flow Bytes/s")
    ax2.set_ylabel("Packet Length Mean")
    plt.colorbar(scatter, label='Anomaly (-1) / Normal (1)')
    st.pyplot(fig2)
    
    # Visualization 3: Bar Plot of Flag Counts
    fig3, ax3 = plt.subplots()
    flag_counts = [
        features_df['FIN Flag Count'].sum(),
        features_df['SYN Flag Count'].sum()
    ]
    flags = ['FIN Flags', 'SYN Flags']
    ax3.bar(flags, flag_counts, color=['orange', 'green'])
    ax3.set_title("Total FIN and SYN Flag Counts")
    ax3.set_ylabel("Count")
    st.pyplot(fig3)
    
    # Visualization 4: Correlation Heatmap of Features
    fig4, ax4 = plt.subplots()
    corr_matrix = features_df.drop(columns=['Anomaly']).corr()
    sns.heatmap(corr_matrix, annot=True, cmap='viridis', fmt=".2f", ax=ax4)
    ax4.set_title("Correlation Heatmap of Features")
    st.pyplot(fig4)
    
    # Visualization 5: Pie Chart of Anomaly vs Normal
    fig5, ax5 = plt.subplots()
    labels = ['Normal', 'Anomaly']
    sizes = [total_flows - anomaly_count, anomaly_count]
    ax5.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=['lightgreen', 'salmon'])
    ax5.axis('equal')
    ax5.set_title("Anomaly Distribution")
    st.pyplot(fig5)
    
    # Clean up temporary files
    # os.remove(pcap_path)
    # if os.path.exists(csv_path):
    #     st.download_button("Download anomaly.csv", data=open(csv_path, 'rb'), file_name="anomaly.csv")
else:
    st.info("Please upload a PCAP file to begin.")



# if __name__ == "__main__":
#     input_pcap = "data/raw/sample_data.pcap"
#     output_csv_C = "data/processed/classifer.csv"
#     output_csv_A = "data/processed/anomaly.csv"
#     # classifier_features.extract_flow_features(input_pcap, output_csv_C)

#     anomaly_features.extract_flow_features(input_pcap, output_csv_A)

