( function( blocks, element, blockEditor, components, serverSideRender ) {
	var el = element.createElement;
	var registerBlockType = blocks.registerBlockType;
	var InspectorControls = blockEditor.InspectorControls;
	var TextControl = components.TextControl;
	var SelectControl = components.SelectControl;
	var PanelBody = components.PanelBody;
	var ServerSideRender = serverSideRender || ( window.wp && window.wp.components && window.wp.components.ServerSideRender );

	registerBlockType( 'crypto/price', {
		title: 'Crypto Price',
		description: 'Display live cryptocurrency prices with customizable layouts and themes.',
		icon: 'chart-line',
		category: 'widgets',
		attributes: {
			symbol: {
				type: 'string',
				default: 'BTC',
			},
			convert: {
				type: 'string',
				default: 'USD',
			},
			layout: {
				type: 'string',
				default: 'card',
			},
			theme: {
				type: 'string',
				default: 'glass',
			},
		},
		edit: function( props ) {
			var attributes = props.attributes;
			var setAttributes = props.setAttributes;

			function onChangeSymbol( newSymbol ) {
				setAttributes( { symbol: newSymbol } );
			}

			function onChangeConvert( newConvert ) {
				setAttributes( { convert: newConvert } );
			}

			function onChangeLayout( newLayout ) {
				setAttributes( { layout: newLayout } );
			}

			function onChangeTheme( newTheme ) {
				setAttributes( { theme: newTheme } );
			}

			return [
				el( InspectorControls, { key: 'controls' },
					el( PanelBody, { title: 'Crypto Settings', initialOpen: true },
						el( TextControl, {
							label: 'Cryptocurrency Symbol',
							value: attributes.symbol,
							onChange: onChangeSymbol,
							help: 'e.g. BTC, ETH, SOL'
						} ),
						el( SelectControl, {
							label: 'Currency / Convert To',
							value: attributes.convert,
							onChange: onChangeConvert,
							options: [
								{ label: 'USD ($)', value: 'USD' },
								{ label: 'EUR (€)', value: 'EUR' },
								{ label: 'GBP (£)', value: 'GBP' },
								{ label: 'JPY (¥)', value: 'JPY' },
								{ label: 'CAD ($)', value: 'CAD' },
								{ label: 'AUD ($)', value: 'AUD' },
								{ label: 'INR (₹)', value: 'INR' },
								{ label: 'CNY (¥)', value: 'CNY' },
								{ label: 'RUB (₽)', value: 'RUB' },
								{ label: 'BTC (₿)', value: 'BTC' },
								{ label: 'ETH (Ξ)', value: 'ETH' }
							]
						} ),
						el( SelectControl, {
							label: 'Layout',
							value: attributes.layout,
							onChange: onChangeLayout,
							options: [
								{ label: 'Card', value: 'card' },
								{ label: 'Badge', value: 'badge' }
							]
						} ),
						el( SelectControl, {
							label: 'Theme',
							value: attributes.theme,
							onChange: onChangeTheme,
							options: [
								{ label: 'Glassmorphism', value: 'glass' },
								{ label: 'Dark', value: 'dark' },
								{ label: 'Light', value: 'light' }
							]
						} )
					)
				),
				el( 'div', { key: 'preview', className: 'crypto-block-preview' },
					ServerSideRender
						? el( ServerSideRender, {
								block: 'crypto/price',
								attributes: attributes
						  } )
						: el( 'div', { className: 'crypto-error-notice' }, 'Preview is not available in this editor version.' )
				)
			];
		},
		save: function() {
			// Dynamic block, rendered on server-side
			return null;
		},
	} );
} )(
	window.wp.blocks,
	window.wp.element,
	window.wp.blockEditor || window.wp.editor,
	window.wp.components,
	window.wp.serverSideRender
);
