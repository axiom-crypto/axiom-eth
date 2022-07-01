extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput};

#[proc_macro_derive(AnyCircuit)]
pub fn any_circuit_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let variants = match input.data {
        Data::Enum(data_enum) => data_enum.variants,
        _ => panic!("AnyCircuit can only be derived for enums"),
    };

    let read_or_create_pk_arms = variants.iter().map(|variant| {
        let ident = &variant.ident;
        quote! {
            Self::#ident(pre_circuit) => pre_circuit.read_or_create_pk(params, pk_path, pinning_path, read_only)
        }
    });

    let gen_snark_shplonk_arms = variants.iter().map(|variant| {
        let ident = &variant.ident;
        quote! {
            Self::#ident(pre_circuit) => pre_circuit.gen_snark_shplonk(params, pk, pinning_path, path)
        }
    });

    let gen_evm_verifier_shplonk_arms = variants.iter().map(|variant| {
        let ident = &variant.ident;
        quote! {
            Self::#ident(pre_circuit) => pre_circuit.gen_evm_verifier_shplonk(params, pk, yul_path)
        }
    });

    let gen_calldata_arms = variants.iter().map(|variant| {
        let ident = &variant.ident;
        quote! {
            Self::#ident(pre_circuit) => pre_circuit.gen_calldata(params, pk, pinning_path, path, deployment_code)
        }
    });

    let expanded = quote! {
        impl #impl_generics AnyCircuit for #name #ty_generics #where_clause {
            fn read_or_create_pk(
                self,
                params: &ParamsKZG<Bn256>,
                pk_path: impl AsRef<Path>,
                pinning_path: impl AsRef<Path>,
                read_only: bool,
            ) -> ProvingKey<G1Affine> {
                match self {
                    #(#read_or_create_pk_arms,)*
                }
            }

            fn gen_snark_shplonk(
                self,
                params: &ParamsKZG<Bn256>,
                pk: &ProvingKey<G1Affine>,
                pinning_path: impl AsRef<Path>,
                path: Option<impl AsRef<Path>>,
            ) -> Snark {
                match self {
                    #(#gen_snark_shplonk_arms,)*
                }
            }

            fn gen_evm_verifier_shplonk(
                self,
                params: &ParamsKZG<Bn256>,
                pk: &ProvingKey<G1Affine>,
                yul_path: impl AsRef<Path>,
            ) -> Vec<u8> {
                match self {
                    #(#gen_evm_verifier_shplonk_arms,)*
                }
            }

            fn gen_calldata(
                self,
                params: &ParamsKZG<Bn256>,
                pk: &ProvingKey<G1Affine>,
                pinning_path: impl AsRef<Path>,
                path: impl AsRef<Path>,
                deployment_code: Option<Vec<u8>>,
            ) -> String {
                match self {
                    #(#gen_calldata_arms,)*
                }
            }
        }
    };

    TokenStream::from(expanded)
}
