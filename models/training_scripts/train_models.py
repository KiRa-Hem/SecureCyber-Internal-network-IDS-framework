#!/usr/bin/env python3
"""
Train machine learning models for IDS/IPS system
"""

import os
import sys
import numpy as np
import pickle
import torch
import torch.nn as nn
import torch.optim as optim
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Define neural network model
class DNNModel(nn.Module):
    def __init__(self, input_size, hidden_size, num_classes):
        super(DNNModel, self).__init__()
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(hidden_size, hidden_size)
        self.fc3 = nn.Linear(hidden_size, num_classes)
        self.dropout = nn.Dropout(0.2)
    
    def forward(self, x):
        out = self.fc1(x)
        out = self.relu(out)
        out = self.dropout(out)
        out = self.fc2(out)
        out = self.relu(out)
        out = self.dropout(out)
        out = self.fc3(out)
        return out

def load_data():
    """Load preprocessed data"""
    data_dir = Path(__file__).parent / "data"
    
    X_train = np.load(data_dir / "X_train.npy")
    X_test = np.load(data_dir / "X_test.npy")
    y_binary_train = np.load(data_dir / "y_binary_train.npy")
    y_binary_test = np.load(data_dir / "y_binary_test.npy")
    y_category_train = np.load(data_dir / "y_category_train.npy")
    y_category_test = np.load(data_dir / "y_category_test.npy")
    
    # Load preprocessors and encoders
    with open(data_dir / "preprocessor.pkl", 'rb') as f:
        preprocessor = pickle.load(f)
    
    with open(data_dir / "le_binary.pkl", 'rb') as f:
        le_binary = pickle.load(f)
    
    with open(data_dir / "le_category.pkl", 'rb') as f:
        le_category = pickle.load(f)
    
    return (X_train, X_test, y_binary_train, y_binary_test, 
            y_category_train, y_category_test, preprocessor, le_binary, le_category)

def train_random_forest(X_train, X_test, y_train, y_test):
    """Train Random Forest model"""
    print("Training Random Forest model...")
    
    # Create and train model
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = rf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Random Forest Accuracy: {accuracy:.4f}")
    
    # Print classification report
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    
    # Plot confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Random Forest Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    
    # Save plot
    models_dir = Path(__file__).parent
    plt.savefig(models_dir / "rf_confusion_matrix.png")
    
    return rf

def train_dnn(X_train, X_test, y_train, y_test, input_size, num_classes):
    """Train Deep Neural Network model"""
    print("Training Deep Neural Network model...")
    
    # Convert to PyTorch tensors
    X_train_tensor = torch.FloatTensor(X_train)
    y_train_tensor = torch.LongTensor(y_train)
    X_test_tensor = torch.FloatTensor(X_test)
    y_test_tensor = torch.LongTensor(y_test)
    
    # Create model
    hidden_size = 128
    model = DNNModel(input_size, hidden_size, num_classes)
    
    # Define loss and optimizer
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    # Training loop
    num_epochs = 20
    batch_size = 64
    
    train_dataset = torch.utils.data.TensorDataset(X_train_tensor, y_train_tensor)
    train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    
    print("Training DNN...")
    for epoch in range(num_epochs):
        for i, (inputs, labels) in enumerate(train_loader):
            # Forward pass
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            
            # Backward and optimize
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
        
        if (epoch + 1) % 5 == 0:
            print(f'Epoch [{epoch+1}/{num_epochs}], Loss: {loss.item():.4f}')
    
    # Evaluate model
    model.eval()
    with torch.no_grad():
        outputs = model(X_test_tensor)
        _, predicted = torch.max(outputs.data, 1)
        accuracy = (predicted == y_test_tensor).sum().item() / len(y_test_tensor)
        print(f"DNN Accuracy: {accuracy:.4f}")
    
    # Print classification report
    print("Classification Report:")
    print(classification_report(y_test_tensor.numpy(), predicted.numpy()))
    
    # Plot confusion matrix
    cm = confusion_matrix(y_test_tensor.numpy(), predicted.numpy())
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('DNN Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    
    # Save plot
    models_dir = Path(__file__).parent
    plt.savefig(models_dir / "dnn_confusion_matrix.png")
    
    return model

def main():
    # Load data
    (X_train, X_test, y_binary_train, y_binary_test, 
     y_category_train, y_category_test, preprocessor, le_binary, le_category) = load_data()
    
    # Train Random Forest for binary classification
    rf_model = train_random_forest(X_train, X_test, y_binary_train, y_binary_test)
    
    # Train DNN for multi-class classification
    input_size = X_train.shape[1]
    num_classes = len(le_category.classes_)
    dnn_model = train_dnn(X_train, X_test, y_category_train, y_category_test, input_size, num_classes)
    
    # Save models
    models_dir = Path(__file__).parent
    print(f"Saving models to {models_dir}...")
    
    # Save Random Forest model
    with open(models_dir / "attack_classifier_rf.pkl", 'wb') as f:
        pickle.dump(rf_model, f)
    
    # Save DNN model
    torch.save(dnn_model.state_dict(), models_dir / "attack_classifier_dnn.pth")
    
    # Save preprocessors and encoders
    with open(models_dir / "preprocessor.pkl", 'wb') as f:
        pickle.dump(preprocessor, f)
    
    with open(models_dir / "le_binary.pkl", 'wb') as f:
        pickle.dump(le_binary, f)
    
    with open(models_dir / "le_category.pkl", 'wb') as f:
        pickle.dump(le_category, f)
    
    print("Training complete!")

if __name__ == "__main__":
    main()