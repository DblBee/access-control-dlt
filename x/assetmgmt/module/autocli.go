package assetmgmt

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	"acmain/x/assetmgmt/types"
)

// AutoCLIOptions implements the autocli.HasAutoCLIConfig interface.
func (am AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service: types.Query_serviceDesc.ServiceName,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "Params",
					Use:       "params",
					Short:     "Shows the parameters of the module",
				},
				{
					RpcMethod:      "Asset",
					Use:            "asset [asset-id]",
					Short:          "Query Asset",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "asset_id"}},
				},

				{
					RpcMethod:      "Asset",
					Use:            "asset [asset-id]",
					Short:          "Query Asset",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "asset_id"}},
				},

				{
					RpcMethod:      "AssetsByLocation",
					Use:            "assets-by-location [building-id] [floor-id] [zone-id] [pagination]",
					Short:          "Query AssetsByLocation",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "building_id"}, {ProtoField: "floor_id"}, {ProtoField: "zone_id"}, {ProtoField: "pagination"}},
				},

				{
					RpcMethod:      "AssetsByLocation",
					Use:            "assets-by-location [building-id] [floor-id] [zone-id] [pagination]",
					Short:          "Query AssetsByLocation",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "building_id"}, {ProtoField: "floor_id"}, {ProtoField: "zone_id"}, {ProtoField: "pagination"}},
				},

				{
					RpcMethod:      "AssetsByLocation",
					Use:            "assets-by-location [building-id] [floor-id] [zone-id] [pagination]",
					Short:          "Query AssetsByLocation",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "building_id"}, {ProtoField: "floor_id"}, {ProtoField: "zone_id"}, {ProtoField: "pagination"}},
				},

				{
					RpcMethod:      "AssetsByLocation",
					Use:            "assets-by-location [building-id] [floor-id] [zone-id] [pagination]",
					Short:          "Query AssetsByLocation",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "building_id"}, {ProtoField: "floor_id"}, {ProtoField: "zone_id"}, {ProtoField: "pagination"}},
				},

				{
					RpcMethod:      "AssetsByLocation",
					Use:            "assets-by-location [building-id] [floor-id] [zone-id] [pagination]",
					Short:          "Query AssetsByLocation",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "building_id"}, {ProtoField: "floor_id"}, {ProtoField: "zone_id"}, {ProtoField: "pagination"}},
				},

				{
					RpcMethod:      "AssetsByLocation",
					Use:            "assets-by-location [building-id] [floor-id] [zone-id] [pagination]",
					Short:          "Query AssetsByLocation",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "building_id"}, {ProtoField: "floor_id"}, {ProtoField: "zone_id"}, {ProtoField: "pagination"}},
				},

				{
					RpcMethod:      "AssetsByLocation",
					Use:            "assets-by-location [building-id] [floor-id] [zone-id] [pagination]",
					Short:          "Query AssetsByLocation",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "building_id"}, {ProtoField: "floor_id"}, {ProtoField: "zone_id"}, {ProtoField: "pagination"}},
				},

				{
					RpcMethod:      "AssetsByType",
					Use:            "assets-by-type [asset-type] [building-id] [pagination]",
					Short:          "Query AssetsByType",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "asset_type"}, {ProtoField: "building_id"}, {ProtoField: "pagination"}},
				},

				{
					RpcMethod:      "AssetsByController",
					Use:            "assets-by-controller [controller-address] [building-id] [pagination]",
					Short:          "Query AssetsByController",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "controller_address"}, {ProtoField: "building_id"}, {ProtoField: "pagination"}},
				},

				{
					RpcMethod:      "AssetsByState",
					Use:            "assets-by-state [state] [building-id] [pagination]",
					Short:          "Query AssetsByState",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "state"}, {ProtoField: "building_id"}, {ProtoField: "pagination"}},
				},

				// this line is used by ignite scaffolding # autocli/query
			},
		},
		Tx: &autocliv1.ServiceCommandDescriptor{
			Service:              types.Msg_serviceDesc.ServiceName,
			EnhanceCustomCommand: true, // only required if you want to use the custom command
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "UpdateParams",
					Skip:      true, // skipped because authority gated
				},
				// this line is used by ignite scaffolding # autocli/tx
			},
		},
	}
}
