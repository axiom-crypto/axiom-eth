use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{Data, DeriveInput};

pub fn impl_flatten_derive(ast: &DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let fields = match ast.data {
        Data::Struct(ref data_struct) => &data_struct.fields,
        _ => {
            return quote! {
                compile_error!("CoreBuilderParams macro only supports structs");
            }
        }
    };

    let field_types: Vec<_> = fields
        .iter()
        .map(|field| field.ty.to_token_stream())
        .collect();

    let field_names: Vec<_> = fields
        .iter()
        .map(|field| {
            if let Some(ref field) = field.ident {
                return field.to_token_stream();
            }
            quote! {
                compile_error!("InputFlatten macro only supports named fields");
            }
        })
        .collect();

    let (impl_generics, ty_generics, _) = ast.generics.split_for_impl();

    let num_fe_tokens = field_types.iter().map(|ident| {
        quote! {
            <#ident as crate::utils::flatten::InputFlatten<T>>::NUM_FE
        }
    });
    let num_fe_tokens_clone = num_fe_tokens.clone();

    let flatten_tokens = field_names.iter().map(|ident| {
        quote! {
            self.#ident.flatten_vec(),
        }
    });

    let create_struct_tokens: Vec<_> = field_names
        .iter()
        .zip(field_types.iter())
        .enumerate()
        .map(|(index, (name, field_type))| {
            quote! {
                #name: <#field_type as crate::utils::flatten::InputFlatten<T>>::unflatten(segmented_fe[#index].clone())?,
            }
        })
        .collect();

    quote! {
        impl #impl_generics crate::utils::flatten::InputFlatten<T> for #name #ty_generics {
            const NUM_FE: usize = #(#num_fe_tokens + )* 0;
            fn flatten_vec(&self) -> Vec<T> {
                let flattened = vec![#(#flatten_tokens)*];
                flattened.into_iter().flatten().collect()
            }

            fn unflatten(vec: Vec<T>) -> anyhow::Result<Self> {
                if vec.len() != <Self as crate::utils::flatten::InputFlatten<T>>::NUM_FE {
                    anyhow::bail!(
                        "Invalid input length: {} != {}",
                        vec.len(),
                        <Self as crate::utils::flatten::InputFlatten<T>>::NUM_FE
                    );
                }

                let mut fe = vec.clone();
                let num_fe_per_field = vec![#(#num_fe_tokens_clone),*];

                let mut segmented_fe = Vec::<Vec<T>>::new();
                for num_fe in num_fe_per_field.iter() {
                    let new_vec = fe.drain(0..*num_fe).collect();
                    segmented_fe.push(new_vec);
                }

                Ok(#name {
                    #(#create_struct_tokens)*
                })
            }
        }
        impl #impl_generics #name #ty_generics {
            pub fn flatten(self) -> Vec<T> {
                crate::utils::flatten::InputFlatten::<T>::flatten_vec(&self)
            }
        }

        impl #impl_generics TryFrom<Vec<T>> for #name #ty_generics {
            type Error = anyhow::Error;

            fn try_from(value: Vec<T>) -> anyhow::Result<Self> {
                <Self as crate::utils::flatten::InputFlatten<T>>::unflatten(value)
            }
        }

        impl #impl_generics TryFrom<crate::framework::types::Flatten<T>> for #name #ty_generics {
            type Error = anyhow::Error;

            fn try_from(
                value: crate::framework::types::Flatten<T>,
            ) -> anyhow::Result<Self> {
                if value.field_size.to_vec() != vec![999; <Self as crate::utils::flatten::InputFlatten<T>>::NUM_FE] {
                    anyhow::bail!("invalid field size");
                }
                if value.field_size.len() != value.fields.len() {
                    anyhow::bail!("field length doesn't match");
                }
                let res = value.fields.try_into()?;
                Ok(res)
            }
        }

        impl #impl_generics From<#name #ty_generics> for crate::framework::types::Flatten<T> {
            fn from(value: #name #ty_generics) -> Self {
                let vec = value.flatten().to_vec();
                let field_size_box = vec![999; vec.len()];
                crate::framework::types::Flatten::<T> {
                    fields: vec,
                    field_size: crate::utils::flatten::into_static_slice(field_size_box),
                }
            }
        }

        impl #impl_generics crate::framework::types::FixLenLogical<T> for #name #ty_generics {
            fn get_field_size() -> &'static [usize] {
                let num_fe = <Self as crate::utils::flatten::InputFlatten<T>>::NUM_FE;
                let vec = vec![999; num_fe];
                crate::utils::flatten::into_static_slice(vec)
            }
        }
    }
}
