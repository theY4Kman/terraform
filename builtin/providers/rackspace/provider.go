package rackspace

import (
	"os"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

// Provider returns a schema.Provider for OpenStack.
func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"auth_url": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: envDefaultFunc("RS_AUTH_URL"),
			},
			"username": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: envDefaultFunc("RS_USERNAME"),
			},
			"api_key": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: envDefaultFunc("RS_API_KEY"),
			},
			"password": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
				Default:  "",
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"rackspace_blockstorage_volume":     resourceBlockStorageVolume(),
			"rackspace_compute_instance":        resourceComputeInstance(),
			"rackspace_compute_keypair":         resourceComputeKeypair(),
			"rackspace_networking_network":      resourceNetworkingNetwork(),
			"rackspace_networking_port":         resourceNetworkingPort(),
			"rackspace_networking_secgroup":     resourceNetworkingSecGroup(),
			"rackspace_networking_secgrouprule": resourceNetworkingSecGroupRule(),
			"rackspace_networking_subnet":       resourceNetworkingSubnet(),
		},

		ConfigureFunc: configureProvider,
	}
}

func configureProvider(d *schema.ResourceData) (interface{}, error) {
	config := Config{
		IdentityEndpoint: d.Get("auth_url").(string),
		Username:         d.Get("username").(string),
		Password:         d.Get("password").(string),
		APIKey:           d.Get("api_key").(string),
	}

	if err := config.loadAndValidate(); err != nil {
		return nil, err
	}

	return &config, nil
}

func envDefaultFunc(k string) schema.SchemaDefaultFunc {
	return func() (interface{}, error) {
		if v := os.Getenv(k); v != "" {
			return v, nil
		}

		return nil, nil
	}
}

func envDefaultFuncAllowMissing(k string) schema.SchemaDefaultFunc {
	return func() (interface{}, error) {
		v := os.Getenv(k)
		return v, nil
	}
}
