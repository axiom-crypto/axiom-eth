use proc_macro2::TokenStream;
use syn::{Data, DeriveInput};

pub fn impl_params_derive(ast: &DeriveInput) -> TokenStream {
    let name = &ast.ident;

    match ast.data {
        Data::Struct(ref data_struct) => {
            for field in data_struct.fields.iter() {
                if let Some(ref ident) = field.ident {
                    if ident == "capacity" {
                        return quote! {
                            impl crate::framework::circuit::CoreBuilderParams for #name {
                                fn get_output_params(&self) -> crate::framework::circuit::CoreBuilderOutputParams {
                                    crate::framework::circuit::CoreBuilderOutputParams::new(vec![self.capacity])
                                }
                            }
                        };
                    }
                }
            }
            quote! {
                compile_error!("Struct does not have a 'capacity' field");
            }
        }
        _ => quote! {
            compile_error!("CoreBuilderParams macro only supports structs");
        },
    }
}
