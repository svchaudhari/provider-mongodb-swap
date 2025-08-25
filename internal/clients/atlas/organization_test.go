package organization

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jarcoal/httpmock"
)

func TestClient_GetOrganization(t *testing.T) {
	type fields struct {
		creds Credentials
	}
	type args struct {
		ctx   context.Context
		orgID string
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		mockHTTP func()
		want     GetOrgResponse
		wantErr  bool
	}{
		{
			name:   "Default",
			fields: fields{},
			args:   args{context.Background(), "orgID123"},
			mockHTTP: func() {
				httpmock.RegisterResponder("GET", "https://cloud.mongodb.com/api/atlas/v1.0/orgs/orgID123",
					httpmock.NewStringResponder(200, `{
						"id": "32b6e34b3d91647abb20e7b8",
						"isDeleted": false,
						"links": [
						  {
							"href": "https://cloud.mongodb.com/api/atlas",
							"rel": "self"
						  }
						],
						"name": "org-name"
					  }`))
			},
			want: GetOrgResponse{
				IsDeleted: false,
				Name:      "org-name",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := &Client{
				rootCredentials: tt.fields.creds,
				orgCredentials:  &tt.fields.creds,
			}

			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			tt.mockHTTP()

			got, err := c.GetOrganization(tt.args.ctx, tt.args.orgID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetOrganization() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Client.GetOrganization() = %v, want %v", got, tt.want)
			}
		})
	}
}
