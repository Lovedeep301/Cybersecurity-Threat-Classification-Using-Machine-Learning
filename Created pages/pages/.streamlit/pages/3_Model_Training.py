import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import time
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from utils.model import ThreatDetectionModel

st.set_page_config(
    page_title="Model Training - Cybersecurity Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🧠 Model Training")

# Check if data exists in session state
if st.session_state.data is None:
    st.warning("No data available. Please upload security logs in the Data Upload page.")
    st.stop()

data = st.session_state.data

# Display current model status
if st.session_state.trained:
    st.success("Model is trained and ready to use!")
else:
    st.info("Using default model. Train a custom model for improved accuracy.")

# Add an explanation of the model training process
st.markdown("""
## Model Training Process

Training a custom machine learning model for threat detection involves:

1. **Feature Selection**: Choose the most relevant features from the log data
2. **Data Splitting**: Divide data into training and testing sets
3. **Model Configuration**: Set parameters for the machine learning algorithm
4. **Training**: Train the model on the prepared data
5. **Evaluation**: Assess the model's performance with various metrics

This will create a model tailored to your specific network environment and threat patterns.
""")

# Check if we have enough data for training
if len(data) < 20:
    st.warning("Not enough data for reliable model training. Upload more logs or use sample data.")
    can_train = False
else:
    can_train = True

# Model training section
st.subheader("Train Custom Threat Detection Model")

with st.form("model_training_form"):
    # Feature selection
    st.markdown("### Feature Selection")
    
    available_features = [col for col in data.columns if col not in ['is_threat', 'threat_type']]
    
    selected_features = st.multiselect(
        "Select features to use for training",
        available_features,
        default=available_features[:min(len(available_features), 5)]  # Select up to 5 features by default
    )
    
    # Model configuration
    st.markdown("### Model Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        model_type = st.selectbox(
            "Select model type",
            ["Random Forest", "Gradient Boosting", "Logistic Regression"]
        )
        
        test_size = st.slider(
            "Test set size (%)",
            min_value=10,
            max_value=50,
            value=20,
            step=5
        ) / 100
    
    with col2:
        if model_type == "Random Forest":
            n_estimators = st.slider("Number of trees", 50, 300, 100, 50)
            max_depth = st.slider("Maximum tree depth", 3, 15, 7, 1)
        elif model_type == "Gradient Boosting":
            n_estimators = st.slider("Number of estimators", 50, 300, 100, 50)
            learning_rate = st.slider("Learning rate", 0.01, 0.3, 0.1, 0.01)
        elif model_type == "Logistic Regression":
            c_param = st.slider("Regularization (C)", 0.1, 10.0, 1.0, 0.1)
            max_iter = st.slider("Maximum iterations", 100, 1000, 500, 100)
    
    # Manual labeling option
    st.markdown("### Labeling (Optional)")
    do_manual_labeling = st.checkbox("Manually label some entries as threats before training")
    
    # Submit button
    submit_button = st.form_submit_button("Train Model")

# Handle manual labeling if selected
if can_train and do_manual_labeling and 'manual_labeling_done' not in st.session_state:
    st.subheader("Manual Threat Labeling")
    st.markdown("Select entries that should be labeled as threats:")
    
    # Display a sample of data for manual labeling
    sample_size = min(20, len(data))
    if 'labeling_sample' not in st.session_state:
        st.session_state.labeling_sample = data.sample(sample_size).reset_index(drop=True)
    
    # Create checkboxes for each entry
    manual_labels = []
    for i, row in st.session_state.labeling_sample.iterrows():
        # Create a readable representation of the log entry
        if 'source_ip' in row and 'event_type' in row:
            entry_desc = f"{row.get('timestamp', 'Unknown')} - {row['source_ip']} - {row['event_type']}"
        else:
            entry_desc = f"Entry {i+1}"
        
        is_threat = st.checkbox(f"{entry_desc}", value=False, key=f"label_{i}")
        manual_labels.append(is_threat)
    
    if st.button("Submit Manual Labels"):
        # Update the labels in the sample
        st.session_state.labeling_sample['is_threat'] = [1 if label else 0 for label in manual_labels]
        
        # Update the main dataset with these manual labels
        for i, row in st.session_state.labeling_sample.iterrows():
            # Find matching rows in the main dataset (simplified matching)
            if 'source_ip' in data.columns and 'timestamp' in data.columns:
                match_idx = data[(data['source_ip'] == row['source_ip']) & 
                                (data['timestamp'] == row['timestamp'])].index
                if not match_idx.empty:
                    data.loc[match_idx[0], 'is_threat'] = row['is_threat']
        
        # Update the session state
        st.session_state.data = data
        st.session_state.manual_labeling_done = True
        st.success("Manual labels applied successfully!")
        st.rerun()

# Process form submission
if can_train and submit_button:
    if not selected_features:
        st.error("Please select at least one feature for training.")
    else:
        with st.spinner("Training model..."):
            # Prepare data for training
            X = data[selected_features]
            y = data['is_threat'] if 'is_threat' in data.columns else np.zeros(len(data))
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
            
            # Initialize and configure model
            model = ThreatDetectionModel()
            
            # Configure model parameters based on selection
            if model_type == "Random Forest":
                model_params = {
                    'model_type': 'random_forest',
                    'n_estimators': n_estimators,
                    'max_depth': max_depth
                }
            elif model_type == "Gradient Boosting":
                model_params = {
                    'model_type': 'gradient_boosting',
                    'n_estimators': n_estimators,
                    'learning_rate': learning_rate
                }
            elif model_type == "Logistic Regression":
                model_params = {
                    'model_type': 'logistic_regression',
                    'C': c_param,
                    'max_iter': max_iter
                }
            
            # Train the model
            model.train(X_train, y_train, model_params)
            
            # Make predictions on test data
            y_pred = model.predict(X_test[selected_features])
            
            # Calculate metrics
            if len(np.unique(y_test)) > 1:  # Only calculate if there are both classes
                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred, zero_division=0)
                recall = recall_score(y_test, y_pred, zero_division=0)
                f1 = f1_score(y_test, y_pred, zero_division=0)
            else:
                accuracy = precision = recall = f1 = 0.0
            
            # Update session state
            st.session_state.model = model
            st.session_state.trained = True
            
            # Re-predict on all data
            st.session_state.predictions = model.predict(data[selected_features])
            data['is_threat'] = st.session_state.predictions
            st.session_state.data = data
            
            # Create a confusion matrix
            if len(np.unique(y_test)) > 1:
                cm = confusion_matrix(y_test, y_pred)
                
                # Calculate true/false positives/negatives
                if cm.shape == (2, 2):
                    tn, fp, fn, tp = cm.ravel()
                    true_negative = tn
                    false_positive = fp
                    false_negative = fn
                    true_positive = tp
                else:
                    true_negative = false_positive = false_negative = true_positive = 0
            else:
                true_negative = len(y_test)
                false_positive = false_negative = true_positive = 0
            
            # Display training results
            st.success("Model training completed!")
            
            # Metrics display
            st.subheader("Model Performance Metrics")
            
            metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
            
            with metric_col1:
                st.metric("Accuracy", f"{accuracy:.2f}")
            
            with metric_col2:
                st.metric("Precision", f"{precision:.2f}")
            
            with metric_col3:
                st.metric("Recall", f"{recall:.2f}")
            
            with metric_col4:
                st.metric("F1 Score", f"{f1:.2f}")
            
            # Confusion matrix visualization
            st.subheader("Confusion Matrix")
            
            cm_col1, cm_col2 = st.columns(2)
            
            with cm_col1:
                st.metric("True Negatives", true_negative)
                st.metric("False Negatives", false_negative)
            
            with cm_col2:
                st.metric("False Positives", false_positive)
                st.metric("True Positives", true_positive)
            
            # Feature importance
            if model_type in ["Random Forest", "Gradient Boosting"]:
                st.subheader("Feature Importance")
                
                # Get feature importance
                feature_importance = model.get_feature_importance(selected_features)
                
                # Create feature importance plot
                fig, ax = plt.subplots(figsize=(10, 6))
                ax.barh(range(len(feature_importance)), feature_importance, align='center')
                ax.set_yticks(range(len(feature_importance)))
                ax.set_yticklabels(selected_features)
                ax.set_xlabel('Importance')
                ax.set_title('Feature Importance')
                
                st.pyplot(fig)

# Navigation hints
st.markdown("---")
st.info("💡 Tip: Check the Alerts page to see notifications for detected threats.")
