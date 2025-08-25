/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// VPCEndpointParameters are the configurable fields of a AWSPrivateLink.
type VPCEndpointParameters struct {
	VpcID            string   `json:"vpcId"`           // example vpc-03a75e9d856407da5
	ServiceName      string   `json:"serviceName"`     // example com.amazonaws.vpce.eu-central-1.vpce-svc-02c21ee840752cff7
	AccountID        string   `json:"accountId"`       // example 198927051560
	SubnetIDs        []string `json:"subnetIds"`       // example [ subnet-000ff8403aca2347d ]
	SecurityGroupIDs []string `json:"securityIds"`     // example [ sg-0333847892bf56879 ]
	Region           string   `json:"region"`          // example eu-central-1
	IPAddressType    string   `json:"ipAddressType"`   // example ipv4
	VPCEndpointType  string   `json:"vpcEndpointType"` // example Interface
}

// VPCEndpointObservation are the observable fields of a AWSPrivateLink.
type VPCEndpointObservation struct {
	State         string `json:"state"`
	VpcEndpointID string `json:"vpcEndpointId"`
}

// A VPCEndpointSpec defines the desired state of a AWSPrivateLink.
type VPCEndpointSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       VPCEndpointParameters `json:"forProvider"`
}

// A VPCEndpointStatus represents the observed state of a AWSPrivateLink.
type VPCEndpointStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          VPCEndpointObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A VPCEndpoint is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,mongodb}
type VPCEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VPCEndpointSpec   `json:"spec"`
	Status VPCEndpointStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VPCEndpointList contains a list of AWSPrivateLink
type VPCEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPCEndpoint `json:"items"`
}

// AWSPrivateLink type metadata.
var (
	VPCEndpointKind             = reflect.TypeOf(VPCEndpoint{}).Name()
	VPCEndpointGroupKind        = schema.GroupKind{Group: Group, Kind: VPCEndpointKind}.String()
	VPCEndpointKindAPIVersion   = VPCEndpointKind + "." + SchemeGroupVersion.String()
	VPCEndpointGroupVersionKind = SchemeGroupVersion.WithKind(VPCEndpointKind)
)

func init() {
	SchemeBuilder.Register(&VPCEndpoint{}, &VPCEndpointList{})
}
